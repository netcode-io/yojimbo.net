# CLAUDE.md

C# and TypeScript ports of the yojimbo C++ network library (with netcode, reliable, serialize and the libsodium subset netcode uses). To *use* the library in a game, read [INTEGRATION.md](INTEGRATION.md). This file is for working *on* the ports.

## Layout

- `cpp/`: upstream yojimbo as a git submodule (`mas-bandwidth/yojimbo`, pinned at 1.13.5). The reference every port follows. Never edit it; to move to a new upstream version, bump the pin.
- `cs/`: C# port, .NET 10. Library `cs/yojimbo.csproj` (NuGet id `yojimbo`), executables `test`, `custom_packet_io_test`, `fuzz`, `client`, `server`, `loopback` and `soak`, all in `cs/yojimbo.slnx`.
- `ts/`: TypeScript port for Node 24+ and browsers. `ts/webrtc/` adds browser clients over WebRTC; it is an extension, not an upstream mirror.
- `interop/`: runs C++, C# and TypeScript against each other in all nine server/client pairings.

## Mirroring rules (keep them)

- File for file with `cpp/`: `include/yojimbo_X.h` + `source/yojimbo_X.cpp` collapse into `{cs,ts}/source/yojimbo_X.{cs,ts}`; a header with no source goes to `{cs,ts}/include/`. `netcode/`, `reliable/`, `serialize/`, `fuzz/` and the top-level tests and samples keep their upstream names. `sodium/sodium.c` maps to `ts/sodium/sodium.ts` only; C# uses BouncyCastle.
- Library tests live inside the library file, as upstream (`netcode_test`, `reliable_test`, `serialize_test`).
- Keep upstream names and the order of members within each file, so an upstream diff can be applied by reading it side by side. Where a port must deviate, say so in a comment at the deviation.
- The wire format must stay byte-identical to upstream. `interop/run.sh` is the proof; run it after anything that touches packets, serialization or crypto.

## Commands

```bash
dotnet build cs/yojimbo.slnx                                  # add -c Release for release
dotnet cs/bin/test/Debug/test.dll                             # 147 tests: serialize, netcode, reliable, yojimbo
dotnet cs/bin/custom_packet_io_test/Debug/custom_packet_io_test.dll
dotnet cs/bin/fuzz/Debug/fuzz.dll                             # upstream fuzz corpus replay + seeded mutation
cd ts && npm ci && npm test                                   # 212 tests (node test.ts)
cd ts && npm run typecheck && npm run build && npm run test:webrtc
interop/run.sh                                                # needs cc/c++, .NET 10, Node 24
```

- **Tests bind fixed UDP ports** (40000, 30000, ...), so never run two suites at the same time. A "bind failed" or "server_create failed" error often just means another run held the port; rerun before debugging.
- **CI:** `.github/workflows/cs.yml` runs C# on Linux, macOS and Windows plus interop; `ts.yml` runs TypeScript on all three. Both must stay green.

## Port conventions

- **C#:** C-style names as upstream (`netcode.client_create`, `reliable.endpoint_send_packet`, the `yojimbo` static class for free functions). The stream `serialize_*` extension methods return bool; every call site must propagate a failure. The allocator semantics are real (error level, leak tracking, failure injection in tests).
- **TypeScript:** see [ts/README.md](ts/README.md).
  - The code is ESM, with `erasableSyntaxOnly` (no enums or namespaces).
  - Relative imports use the `.ts` extension.
  - Integers up to 32 bits are `number`; 64-bit values are `bigint`.
  - Serialize calls use the slot API, `serialize_x(stream, obj, 'field', ...)`.
  - No `node:` imports outside the platform seams: netcode's dgram socket layer loads through `process.getBuiltinModule`, and `webrtc_server.ts` is Node-only.
- **Node event loop:** sockets deliver only while the event loop runs. Node reads at most 32 datagrams per socket per turn on macOS and Linux, and one on Windows. Loops over real sockets must await between frames, and test pumps yield a fixed number of turns (see `PumpEventLoopTurns` in `ts/test.ts`).

## Syncing with upstream

1. Fetch upstream in `cpp/` and diff the pinned commit against the new one (`git -C cpp log/diff <pin>..<new>`).
2. Port each changed upstream file into its mirrored C# and TypeScript files. Port new upstream tests too.
3. Bump the submodule pin, update the version numbers (`cs/yojimbo.csproj`, `ts/package.json`, the version constants) and the README.
4. Run every command above, including `interop/run.sh`.

## Working here

- The user wants work committed and pushed straight to `master` when they ask. There are no PRs. The `ssh-agent` may have no keys loaded; pushing over HTTPS with `gh` credentials works: `git -c credential.helper='!gh auth git-credential' push https://github.com/netcode-io/yojimbo.net.git master`.
- Prefer self-owned code to dependencies. The ChaCha20/Poly1305 port is ours on purpose.
- Don't add abstraction layers for two fixed implementations. WebRTC is exactly native browser APIs plus `node-datachannel`.
