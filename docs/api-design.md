# API design

The surface every binding exposes, and the conventions that keep it small,
marshalable, and identical across languages. Grounded in the FFI patterns of
libsignal, automerge, and matrix-rust-sdk.

Governing decision: [NET-ADR-009](adr/NET-ADR-009-versioning-and-binding-sequence.md).

---

## Two layers per language

Every binding is two layers, the pattern all three reference projects use:

1. **A generated raw layer**, one-to-one with the Rust FFI entry points. Machine-
   produced (napi macro, wasm-bindgen, UniFFI, pyo3), never hand-edited. This is
   where marshalling lives.
2. **A thin idiomatic layer**, hand-written per language, that consumers actually
   use. It turns the raw handles and byte buffers into the language's natural
   shapes (a JS class, a Swift struct, a Python object) and its native error
   channel. It adds no protocol behavior.

Consumers see only the idiomatic layer. The raw layer keeps the FFI boundary
mechanical and driftless.

---

## The boundary is small and typed

The core exposes a deliberately narrow surface. The principles, each with a reason:

**Opaque handles for stateful objects.** A `Client`, a `Dht`, a `Sync` are opaque
handles wrapping the real Rust type (the libsignal and automerge pattern:
`struct Handle(RealType)` with `Deref`). Internal types never cross the boundary.
The host holds a pointer and calls methods; it cannot see or depend on internals.

**Bytes cross as length-delimited buffers.** Everything binary, a BoC, a proof, a
signed message, an ADNL address, crosses as a `(pointer, length)` buffer, mapped
to each host's native bytes type (`Uint8Array`, `Data`, `ByteArray`, `bytes`).
Where a runtime supports it, the transfer is zero-copy; where it does not (the
RustBuffer copy in UniFFI, the Electron buffer copy in napi), it copies. No binary
value is stringified.

**Results are typed, and a proven result is a different type from an unproven
one.** This is the load-bearing API rule. `getAccount` returns a `VerifiedAccount`;
a raw `runSmcMethod` returns a `ServerReportedResult`; a local TVM call returns a
`TvmResult`. The type system, in every binding, makes it impossible to mistake a
server-trusted value for a proof-verified one. Trust level is encoded in the type,
not in documentation a consumer might not read.

**Errors are a closed enum, converted to the host's native channel.** The core
defines a flat error enum (`NotFound`, `BadProof`, `BadSignature`, `Timeout`,
`TransportError`, `ParseError`, ...). Each binding converts it to a thrown JS
error, a Swift `Error`, a Kotlin exception, a Python exception, following
matrix-rust-sdk's flattening: internal Rust error trees collapse to a stable,
small set at the boundary so the rich internal detail stays Rust-side and the
consumer sees a clean surface.

**Async is `async fn` at the boundary.** One async Rust surface maps to each
host's idiom (JS Promise, Swift async/await, Kotlin suspend, Dart Future, Python
awaitable). Native targets embed a tokio runtime; wasm uses a single-threaded
executor. The consumer awaits; the runtime plumbing is invisible.

**The trust anchor is explicit in the type surface.** `Sync.anchor(initKeyBlock)`
is a call the consumer must make; there is no hidden default anchor. The one trust
assumption of the whole library is visible in the API, not buried.

**No user key has a place to live.** No method takes, returns, or logs a wallet
key. `sendMessage` takes already-signed bytes. The surface is shaped so a user key
cannot enter it.

---

## The shape, language-neutral

```
Config
  loadMainnet() -> Config
  loadFromUrl(url) -> Config

Client                              // opaque handle over an ADNL-TCP liteserver channel
  connect(config, transport) -> Client
  getAccount(address) -> VerifiedAccount        // proof-verified
  getTransactions(address, from) -> [VerifiedTransaction]
  getConfig(params) -> VerifiedConfig
  runGetMethod(address, method, args) -> TvmResult      // local TVM, trust-minimized
  runSmcMethodRaw(address, method, args) -> ServerReportedResult   // explicitly unverified
  sendMessage(bocBytes) -> SendStatus           // unprovable; verify effects afterward
  close()

Dht                                 // opaque handle over ADNL-UDP  (native only)
  open(config, udpTransport) -> Dht
  resolveAddress(adnl: bytes32) -> AddressList          // signature-verified
  findValue(key) -> Value
  store(record)
  close()

Sync
  anchor(initKeyBlock)              // the single trust assumption, explicit
  currentMasterchain() -> TrustedBlockId

VerifiedAccount   { balance, state, lastTransaction, provenAgainst: TrustedBlockId }
TvmResult         { stack, exitCode, provenInputs: true }
ServerReportedResult { stack, exitCode, proven: false }     // the type says it
```

Naming and error names are the same across bindings; only the surface syntax
differs. A developer who learns ton-net in one language reads it in another.

---

## What the API refuses to do

- **It will not hand back an unverified value shaped like a verified one.** The
  types forbid it.
- **It will not open a socket the runtime cannot open.** In the browser, `Dht` and
  UDP methods are not present; the type surface reflects the transport's limits
  rather than failing at runtime.
- **It will not hide the trust anchor.** `Sync.anchor` is mandatory before a
  trust-minimized read; a consumer cannot get a proven result without having
  stated the assumption it rests on.
- **It will not accept a user key.** There is no parameter for one.
