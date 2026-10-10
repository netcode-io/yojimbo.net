# yojimbo (TypeScript)

npm package: `yojimbo2` (plain `yojimbo` is taken on npm by an unrelated package). Install it with `npm install yojimbo2`, then `import { Client, Server, ... } from 'yojimbo2'`. Subpath entry points: `yojimbo2/webrtc/client`, `yojimbo2/webrtc/server`, `yojimbo2/webrtc/server-http` (Node), `yojimbo2/webrtc/token`, `yojimbo2/netcode`, `yojimbo2/reliable`, `yojimbo2/serialize`, `yojimbo2/sodium`. Versions (shared with the NuGet package) mirror upstream yojimbo with a port revision folded into the patch: `1.13.500` is upstream 1.13.5, and `1.13.501` is the first port fix on top of it. See the root README.

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
- **Transports.** On Node, netcode talks UDP and interoperates with the C++ and C# ports byte for byte. In the browser there is no UDP: clients use WebRTC data channels (unordered, `maxRetransmits: 0`) through yojimbo's custom packet I/O (`Adapter.UseCustomPacketIO`), and the server bridges them. Both ends use the standard `RTCPeerConnection`/`RTCDataChannel` API, with exactly two implementations behind it and no pluggable layer: the browser's own, and [`node-datachannel`](https://github.com/murat-dogan/node-datachannel)'s polyfill on Node. So the server runs on Node (WebRTC plus native UDP) or in a browser page (WebRTC only). Signaling is one offer and one answer: the client sends its SDP offer (with its connect token) to the game server and gets the answer back, over HTTP or any transport you choose. The netcode packets inside the data channel are the same encrypted packets UDP carries.
- **Crypto is our own port** of libsodium's ChaCha20-Poly1305 (IETF) and XChaCha20-Poly1305, checked against libsodium's known-answer vectors. No crypto dependencies.
- **No runtime dependencies** in the core library.

## WebRTC (browser clients; Node or browser server)

`webrtc/` is an extension, not an upstream mirror. On Node it needs the optional peer dependency `node-datachannel` (for the server, and for clients in tests); browsers use their native WebRTC.

| file | runs on | what |
|---|---|---|
| `webrtc/webrtc_client.ts` | browser (or Node with `node-datachannel/polyfill`) | `WebRTCClientAdapter`: subclass it instead of `Adapter`; `await adapter.connect( signalUrl, connectToken )` (HTTP) or `adapter.connect( connectToken, signal )` (your own transport), then `client.Connect( clientId, connectToken )` as usual. `HttpSignal( url )`, and `CreateNetcodeChannel` (the channel setup both ends share) |
| `webrtc/webrtc_server.ts` | Node and browser | `WebRTCServerAdapter`: one yojimbo `Server` serving WebRTC peers (synthetic addresses in a random `fdXX:XXXX:XXXX:5754::/64`, never reused) and, on Node, native UDP clients (its own socket on the server address); `accept( { sdp, connectToken, ip } )`, the signaling gate every transport calls; `SignalError`; `GenerateConnectToken`. No `node:*` import, no static `node-datachannel` import |
| `webrtc/webrtc_server_http.ts` | Node only | HTTP signaling over `accept()`: `HandleSignal( adapter, req, res, options )`, `ListenSignaling( adapter, port, { path, cors, clientIp, maxBodyBytes } )`. Re-exports `webrtc_server.ts` |
| `webrtc/webrtc_token.ts` | both | connect token helpers: `GenerateConnectToken`, `ValidateConnectToken` (the signaling gate), base64 |
| `webrtc/webrtc_echo.ts` | both | the interop echo protocol, shared by the tests and the demo |

```bash
npm run test:webrtc     # node webrtc/webrtc_test.ts: WebRTC + UDP clients echo against one server (HTTP and direct accept() signaling), refusals, caps, reaping
npm run build && npm run test:bundle    # esbuild browser bundle of yojimbo2 + webrtc/client + webrtc/server: no node:*, no node-datachannel
npx playwright-core install --only-shell chromium && npm run test:browser   # a server hosted in a headless Chromium page, a second page echoes through it
npm run demo:webrtc     # build, then serve the demo on http://localhost:8080/ (prints PASS / FAIL in the page)
node webrtc/demo/node_client.ts http://localhost:8080      # the same demo client, headless (polyfill)
node ../interop/ts/interop.ts client 40000                  # a native UDP client against the same demo server
```

The demo server (`webrtc/demo/server.ts`) is DEV ONLY: all-zero private key (as `interop/`) and an open `/token` endpoint. Options are environment variables: `HTTP_PORT`, `HTTP_HOST` (`0.0.0.0` to reach it from the LAN), `UDP_ADDRESS`, `WEBRTC_LOG` (libdatachannel log level). `?messages=N` on the page runs a shorter echo.

How it fits together:

- **Signaling** is one offer `{ sdp, connectToken }` answered with `{ sdp }`; ICE is non-trickle on both sides. Over HTTP it is one POST (`application/json`, token as base64) to `HandleSignal`/`ListenSignaling`, which own only the HTTP parts (method, CORS, content type, body size and deadline, JSON, client IP) and hand the rest to `adapter.accept()`. Any other transport (WebSocket, `BroadcastChannel`, a client in the same page) calls `accept()` directly and the client passes a `signal( offer, abort )` function to `connect( token, signal )`; a refusal is a `SignalError( status, reason )` and fails the client's `connect()` as an HTTP error does. The data channel is pre-negotiated on both ends (`negotiated: true, id: 0`, unordered, `maxRetransmits: 0`) and carries the same encrypted netcode packets as UDP.
- **The DoS gate.** The server validates the connect token before it allocates a peer connection: it must decrypt with the server's private key, match the protocol id, be unexpired and list this server's address in its encrypted server list (the checks netcode makes on a connection request). All of it is in `accept()`, whatever the transport. On top: per-IP and global caps on connecting and total peers (429 / 503; per-IP keys on `request.ip`, which can be any per-caller identity, and is skipped when there is none), at most `maxSignalsPerToken` signals per token, and timeouts that reap peers that never open, never send, never complete the netcode handshake, or go idle. A peer is released when netcode disconnects its client or its channel closes. The HTTP layer adds a body size cap (413), content type (415) and method (405) checks.
- **Tokens** come from your backend (the matchmaker), which shares the private key with the game servers; the client posts the same token to `/signal` and passes it to `Client.Connect`. `GenerateConnectToken` is for dev and tests. Set `ClientServerConfig.maxConnectTokenLifetime` to the lifetime your backend issues.
- **Deploying.** Serve the signaling endpoint over HTTPS on the game server (or proxy it there; pass `clientIp` to `ListenSignaling`/`HandleSignal` so per-IP limits see the real client). If the page is on another origin, set `cors: { origins: [ 'https://game.example.com' ] }`. Clients need STUN to get through NATs (`iceServers: [ { urls: 'stun:stun.example.com:3478' } ]`) and TURN for symmetric NATs or UDP-hostile networks (`{ urls: 'turn:turn.example.com:3478', username, credential }`, ideally also `turns:` on 443). A server with a public IP needs no STUN of its own; behind NAT give it `iceServers` too, and open its ICE ports: `rtcConfig: { portRangeBegin, portRangeEnd }`, or `{ enableIceUdpMux: true }` for a single UDP port (node-datachannel fields pass through its polyfill). Call `ShutdownWebRTC()` at process exit so node-datachannel's threads stop.
- **A server in a browser page.** The same `WebRTCServerAdapter`, on the page's own `RTCPeerConnection`: WebRTC only (no UDP), so give the address an explicit port; it is just the identity connect tokens name. Signal with your own transport into `accept()`. The page holds the server private key, so the backend must mint a fresh key per hosted session (and tokens for that session only). See INTEGRATION.md.
- **Moved in this version:** `adapter.handleSignal( req, res )` and `adapter.listenSignaling( port, options )` are now `HandleSignal( adapter, req, res, options )` and `ListenSignaling( adapter, port, options )` in `yojimbo2/webrtc/server-http`, and their options `cors`, `clientIp`, `maxBodyBytes`, `bodyTimeoutMs` moved from the adapter options to them. Everything else in `yojimbo2/webrtc/server` is unchanged (`iceServers` now also takes standard `{ urls, username, credential }` entries).
