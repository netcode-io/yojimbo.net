# yojimbo (TypeScript)

npm package: `yojimbo2` (plain `yojimbo` is taken on npm by an unrelated package).

TypeScript port of yojimbo 1.13.5, with netcode 1.4.8, reliable 1.4.5, serialize and the libsodium subset netcode uses. One codebase runs on Node (24+) and in the browser.

```bash
npm install
npm test            # node test.ts — Node runs the .ts sources directly
npm run typecheck
npm run build       # emits dist/ (JS + .d.ts) for bundlers and browsers
```

## Layout

The port mirrors `cpp/` file for file, like `cs/`:

| upstream (`cpp/`)                              | TypeScript (`ts/`)            |
|------------------------------------------------|-------------------------------|
| `sodium/sodium.c` (vendored libsodium subset)  | `sodium/sodium.ts`            |
| `serialize/serialize.h`                        | `serialize/serialize.ts`      |
| `reliable/reliable.h` + `reliable.c`           | `reliable/reliable.ts`        |
| `netcode/netcode.h` + `netcode.c`              | `netcode/netcode.ts`          |
| `include/yojimbo_X.h` + `source/yojimbo_X.cpp` | `source/yojimbo_X.ts`         |
| `include/yojimbo_X.h` (header only)            | `include/yojimbo_X.ts`        |
| `test.cpp`, `client.cpp`, `shared.h`, …        | `test.ts`, `client.ts`, `shared.ts`, … |

Library tests live in the library file, as upstream (`reliable_test()` is exported from `reliable/reliable.ts`). `test.ts` runs them all.

## Conventions

- **Runs without a build step.** ESM only, `erasableSyntaxOnly`: no `enum`, `namespace` or constructor parameter properties. Constants are `export const NAME = value`. Relative imports use the `.ts` extension.
- **Names follow upstream.** C functions stay `snake_case` module functions (`reliable_endpoint_create`), C structs become classes with the same field names, C++ classes keep their names and `PascalCase` methods. Keep upstream order within a file so upstream diffs map onto the port.
- **Numbers.** Bytes are `Uint8Array`. Integers up to 32 bits are `number` (use `>>> 0`, `Math.imul`, `| 0` to keep uint32/int32 semantics). Values that are 64-bit on the wire or can exceed 2^53 (netcode packet sequences, client id, protocol id, `serialize_uint64`) are `bigint`.
- **Platform neutral core.** No Node-only API outside the platform seams: time is `performance.now()`, randomness is `globalThis.crypto.getRandomValues`. UDP sockets (`node:dgram`) are loaded only by the Node socket layer, so browser bundles never pull them in.
- **Transports.** On Node, netcode talks UDP and interoperates with the C++ and C# ports byte for byte. In the browser there is no UDP: clients use WebRTC data channels (unordered, `maxRetransmits: 0`) through yojimbo's custom packet I/O (`Adapter.UseCustomPacketIO`), and the server bridges them. Exactly two WebRTC stacks, no pluggable layer: the browser's native `RTCPeerConnection`/`RTCDataChannel`, and [`node-datachannel`](https://github.com/murat-dogan/node-datachannel) on the Node server. Signaling is one HTTP POST: the client sends its SDP offer (with its connect token) to the game server and gets the answer back. The netcode packets inside the data channel are the same encrypted packets UDP carries.
- **Crypto is our own port** of libsodium's ChaCha20-Poly1305 (IETF) and XChaCha20-Poly1305, checked against libsodium's known-answer vectors. No crypto dependencies.
- **No runtime dependencies** in the core library.

## WebRTC (browser clients, Node server)

`webrtc/` is an extension, not an upstream mirror. It needs the optional peer dependency `node-datachannel` on the server only; browsers use their native WebRTC.

| file | runs on | what |
|---|---|---|
| `webrtc/webrtc_client.ts` | browser (or Node with `node-datachannel/polyfill`) | `WebRTCClientAdapter`: subclass it instead of `Adapter`; `await adapter.connect( signalUrl, connectToken )`, then `client.Connect( clientId, connectToken )` as usual |
| `webrtc/webrtc_server.ts` | Node only | `WebRTCServerAdapter`: one yojimbo `Server` serving native UDP clients (its own socket on the server address) and WebRTC peers (synthetic addresses in a random `fdXX:XXXX:XXXX:5754::/64`, never reused); `handleSignal( req, res )` / `listenSignaling( port, { path } )`; `GenerateConnectToken` |
| `webrtc/webrtc_token.ts` | both | connect token helpers: `GenerateConnectToken`, `ValidateConnectToken` (the signaling gate), base64 |
| `webrtc/webrtc_echo.ts` | both | the interop echo protocol, shared by the test and the demo |

```bash
npm run test:webrtc     # node webrtc/webrtc_test.ts: WebRTC + UDP clients echo against one server, signaling refusals, reaping
npm run demo:webrtc     # build, then serve the demo on http://localhost:8080/ (prints PASS / FAIL in the page)
node webrtc/demo/node_client.ts http://localhost:8080      # the same demo client, headless (polyfill)
node ../interop/ts/interop.ts client 40000                  # a native UDP client against the same demo server
```

The demo server (`webrtc/demo/server.ts`) is DEV ONLY: all-zero private key (as `interop/`) and an open `/token` endpoint. Options are environment variables: `HTTP_PORT`, `HTTP_HOST` (`0.0.0.0` to reach it from the LAN), `UDP_ADDRESS`, `WEBRTC_LOG` (libdatachannel log level). `?messages=N` on the page runs a shorter echo.

How it fits together:

- **Signaling** is one POST of `{ sdp, connectToken }` (`application/json`, token as base64) answered with `{ sdp }`; ICE is non-trickle on both sides. The data channel is pre-negotiated on both ends (`negotiated: true, id: 0`, unordered, `maxRetransmits: 0`) and carries the same encrypted netcode packets as UDP.
- **The DoS gate.** The server validates the connect token before it allocates a peer connection: it must decrypt with the server's private key, match the protocol id, be unexpired and list this server's address in its encrypted server list (the checks netcode makes on a connection request). On top: per-IP and global caps on connecting and total peers (429 / 503), at most `maxSignalsPerToken` signals per token, a body size cap (413), content type (415) and method (405) checks, and timeouts that reap peers that never open, never send, never complete the netcode handshake, or go idle. A peer is released when netcode disconnects its client or its channel closes.
- **Tokens** come from your backend (the matchmaker), which shares the private key with the game servers; the client posts the same token to `/signal` and passes it to `Client.Connect`. `GenerateConnectToken` is for dev and tests. Set `ClientServerConfig.maxConnectTokenLifetime` to the lifetime your backend issues.
- **Deploying.** Serve the signaling endpoint over HTTPS on the game server (or proxy it there; pass `clientIp` so per-IP limits see the real client). If the page is on another origin, set `cors: { origins: [ 'https://game.example.com' ] }`. Clients need STUN to get through NATs (`iceServers: [ { urls: 'stun:stun.example.com:3478' } ]`) and TURN for symmetric NATs or UDP-hostile networks (`{ urls: 'turn:turn.example.com:3478', username, credential }`, ideally also `turns:` on 443). A server with a public IP needs no STUN of its own; behind NAT give it `iceServers` too, and open its ICE ports: `rtcConfig: { portRangeBegin, portRangeEnd }`, or `{ enableIceUdpMux: true }` for a single UDP port. Call `ShutdownWebRTC()` at process exit so node-datachannel's threads stop.
