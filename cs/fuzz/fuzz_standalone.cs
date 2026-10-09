/*
    Standalone driver for the fuzz targets (fuzz_standalone.h upstream).

    Upstream each target is its own libFuzzer binary, with this driver as the fallback where
    libFuzzer isn't available. The C# port has no libFuzzer, so all five targets share one
    program, and with no arguments it runs as a regression test:

      1. replays every seed in cpp/fuzz/corpus/<target> through its target, and checks the
         seeds still decode where the seed generators guarantee they do (every netcode packet
         type decrypts, connect tokens parse, reliable packets deliver, connection seeds read
         back without error) - so the C# readers are checked against bytes the C code wrote;
      2. a seeded mutation pass over that corpus (bit flips, byte sets, inserts, deletes,
         duplicates, truncation, splices between seeds of the same target);
      3. pseudo-random buffers, from the same generator upstream's standalone driver uses.

    Any exception, and any yojimbo / netcode / reliable assert (asserts are live in a Debug
    build), is a failure: the input is written to crash-<target>-<sha1> in the current
    directory and the program exits non-zero.

    usage:
        fuzz [seed]                     run the regression
        fuzz <target> <file>...         replay files through one target, eg. a crash file

    environment:
        FUZZ_ITERS          mutations per seed (default 200)
        FUZZ_RANDOM_ITERS   pseudo-random inputs per target (default 1000)
        FUZZ_CORPUS         corpus root (default: cpp/fuzz/corpus, found by walking up from the program)
*/

using networkprotocol;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using static networkprotocol.yojimbo;

static class fuzz_standalone
{
    class Target
    {
        public string name;
        public Func<byte[], int, int> run;
        public Action reset;                                        // drop long-lived target state before a corpus replay
        public Func<byte[], string> checkSeed;                      // null if the seed decoded as the generator guarantees, else why not
        public Func<string> checkCorpus;                            // null if the corpus as a whole decoded as guaranteed, else why not
    }

    class FuzzAssertException : Exception
    {
        public FuzzAssertException(string message) : base(message) { }
    }

    static readonly bool[] netcodePacketTypesSeen = new bool[netcode.FUZZ_NETCODE_NUM_PACKET_TYPES];

    static readonly Target[] targets =
    {
        new Target
        {
            name = "fuzz_connection",
            run = fuzz_connection.LLVMFuzzerTestOneInput,
            checkSeed = seed => fuzz_connection.g_all_packets_accepted ? null : "a seed packet failed to read back",
        },
        new Target
        {
            name = "fuzz_connection_structured",
            run = fuzz_connection_structured.LLVMFuzzerTestOneInput,
        },
        new Target
        {
            name = "fuzz_netcode",
            run = netcode.fuzz_netcode,
            reset = () => Array.Clear(netcodePacketTypesSeen),
            checkSeed = seed =>
            {
                if (netcode.fuzz_netcode_last_packet_type < 0)
                    return "seed failed to decrypt and read back";
                netcodePacketTypesSeen[netcode.fuzz_netcode_last_packet_type] = true;
                return null;
            },
            checkCorpus = () => netcodePacketTypesSeen.All(seen => seen) ? null : "not every netcode packet type has a seed that reads back",
        },
        new Target
        {
            name = "fuzz_netcode_connect_token",
            run = netcode.fuzz_netcode_connect_token,
            checkSeed = seed => netcode.fuzz_netcode_connect_token_last_result == netcode.OK ? null : "seed failed to parse",
        },
        new Target
        {
            name = "fuzz_reliable",
            run = fuzz_reliable.LLVMFuzzerTestOneInput,
            reset = fuzz_reliable.reset,
            // the small packet delivers directly and the large one delivers once reassembled
            checkCorpus = () => fuzz_reliable.g_received >= 2 ? null : $"seeds delivered {fuzz_reliable.g_received} packets, expected at least 2",
        },
    };

    static Target current;
    static byte[] currentInput;

    static void fail(string origin, string reason)
    {
        var name = $"crash-{current.name}-{Convert.ToHexString(SHA1.HashData(currentInput)).ToLowerInvariant()}";
        File.WriteAllBytes(name, currentInput);
        Console.Write($"\nFAIL {current.name}: {origin}\n{reason}\n\ninput ({currentInput.Length} bytes) written to {Path.GetFullPath(name)}\nreproduce: fuzz {current.name} {name}\n");
        Environment.Exit(1);
    }

    static void run_one(Target target, byte[] input, string origin)
    {
        current = target;
        currentInput = input;
        try
        {
            target.run(input, input.Length);
        }
        catch (Exception e)
        {
            fail(origin, e.ToString());
        }
    }

    static int env_int(string name, int defaultValue)
    {
        var value = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrEmpty(value) ? defaultValue : int.Parse(value);
    }

    static string find_corpus()
    {
        var corpus = Environment.GetEnvironmentVariable("FUZZ_CORPUS");
        if (!string.IsNullOrEmpty(corpus))
            return corpus;
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "cpp", "fuzz", "corpus");
            if (Directory.Exists(candidate))
                return candidate;
        }
        return null;
    }

    static byte[] mutate(Random random, byte[] seed, List<byte[]> seeds)
    {
        var data = new List<byte>(seed);
        var numMutations = 1 + random.Next(4);
        for (var m = 0; m < numMutations; ++m)
        {
            switch (random.Next(8))
            {
                case 0: // flip a bit
                    if (data.Count > 0)
                        data[random.Next(data.Count)] ^= (byte)(1 << random.Next(8));
                    break;

                case 1: // set a random byte
                    if (data.Count > 0)
                        data[random.Next(data.Count)] = (byte)random.Next(256);
                    break;

                case 2: // set an interesting value
                {
                    byte[] interesting = { 0x00, 0x01, 0x7F, 0x80, 0xFF };
                    if (data.Count > 0)
                        data[random.Next(data.Count)] = interesting[random.Next(interesting.Length)];
                    break;
                }

                case 3: // insert random bytes
                {
                    var count = 1 + random.Next(8);
                    var at = random.Next(data.Count + 1);
                    for (var i = 0; i < count; ++i)
                        data.Insert(at, (byte)random.Next(256));
                    break;
                }

                case 4: // delete a range
                    if (data.Count > 0)
                    {
                        var at = random.Next(data.Count);
                        data.RemoveRange(at, 1 + random.Next(Math.Min(16, data.Count - at)));
                    }
                    break;

                case 5: // duplicate a range
                    if (data.Count > 0)
                    {
                        var at = random.Next(data.Count);
                        var count = 1 + random.Next(Math.Min(32, data.Count - at));
                        data.InsertRange(random.Next(data.Count + 1), data.GetRange(at, count));
                    }
                    break;

                case 6: // truncate
                    if (data.Count > 0)
                    {
                        var keep = random.Next(data.Count);
                        data.RemoveRange(keep, data.Count - keep);
                    }
                    break;

                case 7: // splice in the tail of another seed of the same target
                {
                    var other = seeds[random.Next(seeds.Count)];
                    var at = random.Next(data.Count + 1);
                    var from = random.Next(other.Length + 1);
                    data.RemoveRange(at, data.Count - at);
                    data.AddRange(other.Skip(from));
                    break;
                }
            }
        }
        return data.ToArray();
    }

    static int Main(string[] args)
    {
        var parsedSeed = 0u;
        var seedArgument = args.Length == 1 && uint.TryParse(args[0], out parsedSeed);

        if (!InitializeYojimbo())
        {
            Console.Write("error: failed to initialize yojimbo\n");
            return 1;
        }

        // an assert inside a target is a finding: turn it into an exception so the driver can report the input
        set_assert_function((condition, function, file, line) =>
            throw new FuzzAssertException($"assert failed: ( {condition} ), function {function}, file {file}, line {line}"));

        if (args.Length > 0 && !seedArgument)
        {
            // replay files through one target
            var target = targets.FirstOrDefault(t => t.name == args[0]);
            if (target == null)
            {
                Console.Write($"error: unknown target '{args[0]}'. targets: {string.Join(", ", targets.Select(t => t.name))}\n");
                return 1;
            }
            for (var i = 1; i < args.Length; ++i)
                run_one(target, File.ReadAllBytes(args[i]), args[i]);
            Console.Write($"{target.name}: {args.Length - 1} inputs ok\n");
            ShutdownYojimbo();
            return 0;
        }

        var corpusRoot = find_corpus();
        if (corpusRoot == null || !Directory.Exists(corpusRoot))
        {
            Console.Write("error: fuzz corpus not found. check out the cpp submodule (git submodule update --init) or set FUZZ_CORPUS\n");
            return 1;
        }

        var seed = seedArgument ? (int)parsedSeed : 1;
        var mutationsPerSeed = env_int("FUZZ_ITERS", 200);
        var randomIters = env_int("FUZZ_RANDOM_ITERS", 1000);

        Console.Write($"fuzz random seed {(uint)seed}, {mutationsPerSeed} mutations per seed, {randomIters} random inputs per target\ncorpus {Path.GetFullPath(corpusRoot)}\n\n");

        foreach (var target in targets)
        {
            var stopwatch = Stopwatch.StartNew();

            var dir = Path.Combine(corpusRoot, target.name);
            var files = Directory.Exists(dir) ? Directory.GetFiles(dir).OrderBy(f => f, StringComparer.Ordinal).ToArray() : new string[0];
            if (files.Length == 0)
            {
                Console.Write($"error: no seeds for {target.name} in {dir}\n");
                return 1;
            }
            var seeds = files.Select(File.ReadAllBytes).ToList();

            // 1. corpus replay
            target.reset?.Invoke();
            for (var i = 0; i < files.Length; ++i)
            {
                var origin = $"seed {files[i]}";
                run_one(target, seeds[i], origin);
                var reason = target.checkSeed?.Invoke(seeds[i]);
                if (reason != null)
                    fail(origin, reason);
            }
            var corpusReason = target.checkCorpus?.Invoke();
            if (corpusReason != null)
                fail($"corpus {dir}", corpusReason);

            // 2. mutations, seeded per target so a target's inputs don't depend on the targets before it
            var random = new Random(seed ^ StableHash(target.name));
            var mutations = 0;
            for (var i = 0; i < seeds.Count; ++i)
                for (var j = 0; j < mutationsPerSeed; ++j)
                {
                    run_one(target, mutate(random, seeds[i], seeds), $"mutation {j} of seed {files[i]} (fuzz random seed {(uint)seed})");
                    mutations++;
                }

            // 3. pseudo-random buffers, as upstream's standalone driver generates them
            var lcg = 0x1234567u;
            for (var it = 0; it < randomIters; ++it)
            {
                lcg = lcg * 1103515245u + 12345u;
                var n = (int)((lcg >> 8) % (4096 + 1));
                var buf = new byte[n];
                for (var k = 0; k < n; ++k)
                {
                    lcg = lcg * 1103515245u + 12345u;
                    buf[k] = (byte)(lcg >> 16);
                }
                run_one(target, buf, $"random input {it}");
            }

            Console.Write($"{target.name,-28} {seeds.Count,2} seeds ok, {mutations} mutations, {randomIters} random inputs ({stopwatch.Elapsed.TotalSeconds:F1}s)\n");
        }

        fuzz_reliable.reset();

        ShutdownYojimbo();

        Console.Write("\n*** ALL FUZZ TARGETS PASS ***\n\n");

        return 0;
    }

    // string.GetHashCode is randomized per process, so the per-target RNG seed uses this instead
    static int StableHash(string s)
    {
        var hash = 17;
        foreach (var c in s)
            hash = hash * 31 + c;
        return hash;
    }
}
