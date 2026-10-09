# yojimbo.net

**yojimbo.net** holds C# and TypeScript ports of [yojimbo](https://github.com/mas-bandwidth/yojimbo), a network library for client/server games with dedicated servers, along with the two libraries it is built on: [netcode](https://github.com/mas-bandwidth/netcode) and [reliable](https://github.com/mas-bandwidth/reliable).

The ports track upstream **yojimbo 1.13.5** (netcode 1.4.8, reliable 1.4.5). They speak the same wire protocol (`NETCODE 1.02`), so ported clients and servers interoperate with the C/C++ originals.

## Layout

```
cpp/      upstream yojimbo (git submodule) - the reference source every port follows
cs/       C# port (.NET 10)
ts/       TypeScript port (Node 24+ and browsers; WebRTC for browser clients)
legacy/   the original 2019 C# transpile (yojimbo.cs, netcode.io.net, reliable.io.net), kept for reference
```

Each port mirrors the upstream folder layout file for file, so an upstream change maps directly onto the file that needs it:

| upstream (`cpp/`)                                   | C# (`cs/`) and TypeScript (`ts/`)           |
|-----------------------------------------------------|---------------------------------------------|
| `sodium/sodium.c` (libsodium subset)                | `sodium/sodium.ts` (TS only; C# uses BouncyCastle) |
| `netcode/netcode.h` + `netcode/netcode.c`           | `netcode/netcode.cs`                        |
| `reliable/reliable.h` + `reliable/reliable.c`       | `reliable/reliable.cs`                      |
| `serialize/serialize.h`                             | `serialize/serialize.cs`                    |
| `include/yojimbo_X.h` + `source/yojimbo_X.cpp`      | `source/yojimbo_X.cs`                       |
| `include/yojimbo_X.h` (header only)                 | `include/yojimbo_X.cs`                      |
| `test.cpp`, `client.cpp`, `server.cpp`, `shared.h`… | `test.cs`, `client.cs`, `server.cs`, `shared.cs`… |
| `fuzz/fuzz_X.c` / `fuzz/fuzz_X.cpp`                 | `fuzz/fuzz_X.cs`                            |

Rules:

- A header and its source collapse into one file, named after the original and placed where the `.cpp`/`.c` lives. A header with no source stays in `include/`.
- Library tests live in the same file as the library, as they do upstream (`netcode_test()` is in `netcode.cs`, `reliable_test()` in `reliable.cs`).
- Names and structure stay close to the C/C++ so upstream diffs can be applied by reading them side by side.

## Building the C# port

Requires the .NET 10 SDK. Check out with submodules (`git clone --recursive`, or `git submodule update --init`): the fuzz corpus and the interop test use `cpp/`.

```bash
dotnet build cs/yojimbo.slnx
```

```bash
dotnet cs/bin/test/Debug/test.dll
```

```bash
dotnet cs/bin/custom_packet_io_test/Debug/custom_packet_io_test.dll
```

```bash
dotnet cs/bin/fuzz/Debug/fuzz.dll
```

Add `-c Release` to the build and use `bin/<project>/Release/` for a release build. `test` takes an optional random seed (`test <seed>`) to reproduce a failure.

`cs/yojimbo.csproj` is the library (yojimbo with netcode, reliable and serialize compiled in). `test`, `custom_packet_io_test`, `client`, `server`, `loopback` and `soak` are executables that reference it, matching the upstream CMake targets. Debug builds turn on the same checks as upstream's debug build: memory and message leak tracking (a leak asserts when its allocator or message factory is disposed) and the packet budget asserts.

### Allocators

Allocation goes through `Allocator` exactly where upstream calls `YOJIMBO_NEW` / `YOJIMBO_ALLOCATE`, so allocation failure and leak tracking behave like upstream. A C# allocator hands out objects built by a factory rather than raw memory, so it can refuse an allocation before anything is built; the GC reclaims what is freed. `TLSF_Allocator` keeps upstream's contract, a fixed size heap per client (`ClientServerConfig.clientMemory` / `serverPerClientMemory`) that fails with `ALLOCATOR_ERROR_OUT_OF_MEMORY` when full, so a client that exhausts its memory is disconnected. It is a byte budget over the GC, not a port of the TLSF algorithm. Left C++ only: the TLSF heap itself, the raw memory blocks behind the client and server allocators (placeholders in C#), and the netcode/reliable allocator callbacks (their buffers stay managed arrays). See the notes at the top of `cs/source/yojimbo_allocator.cs`.

### Fuzzing

`cs/fuzz` holds the upstream fuzz targets (`cpp/fuzz`). With no libFuzzer for C#, `fuzz` runs them as a regression test: it replays every seed in `cpp/fuzz/corpus` and checks the seeds the C code wrote still decode in C#, then runs a seeded mutation pass over the corpus and a batch of pseudo-random inputs. An exception or assert fails the run and saves the input as `crash-<target>-<sha1>`; `fuzz <target> <file>` replays it. `FUZZ_ITERS` (mutations per seed, default 200) and `FUZZ_RANDOM_ITERS` (random inputs per target, default 1000) make longer runs.

### Package

```bash
dotnet pack cs/yojimbo.csproj -c Release
```

builds the `yojimbo.net` NuGet package (version 1.13.5, matching upstream) with Source Link symbols.

### CI

`.github/workflows/cs.yml` builds Debug and Release on Linux, macOS and Windows, runs `test`, `custom_packet_io_test` and `fuzz`, packs the library, and runs `interop/run.sh` (all nine C++/C#/TypeScript pairings) on Linux and macOS. `.github/workflows/ts.yml` typechecks, tests and builds the TypeScript port and runs its WebRTC test on Linux, macOS and Windows.

## Interop

Unit tests only show that a port agrees with itself. `interop/` runs the ports against each other and against the upstream C++ build:

```bash
interop/run.sh
```

It builds `cpp/` with the system C/C++ compiler (no CMake needed), then runs all nine server/client pairings of C++, C# and TypeScript over UDP. The client sends 1000 reliable-ordered messages (every 8th a block, many multi-fragment) plus unreliable traffic, and verifies every echo. The connect token is generated by the client and decrypted by the server, so mixed pairings also check that the crypto agrees.

## Building the TypeScript port

Requires Node 24+. See [ts/README.md](ts/README.md).

```bash
cd ts && npm install && npm test
```

## Author

yojimbo, netcode and reliable are by [Glenn Fiedler](https://mas-bandwidth.com). See [LICENCE](LICENCE).
