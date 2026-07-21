# Security

ton-net exists to check what a liteserver says rather than believe it. A bug that
lets a server get an unproven answer past that check is the most serious kind of
defect this project can have, and it is treated that way.

## Reporting

Use the repository's **Security** tab, "Report a vulnerability", which opens a
private advisory visible only to the maintainers. Do not open an issue or a pull
request; both are public from the moment they are filed.

A first response should arrive within three days. If one does not, the report was
missed rather than ignored, and it is worth sending again.

A report is most useful with the version or commit, what the attacker controls,
and what they get. A proof-of-concept is welcome and is not required.

## Supported versions

Nothing is published to a registry yet. The first ordinary release is v0.3.0; from
then on the latest release line carries fixes. Before that, `main` is the only
supported version.

## What is in scope

The high-severity classes, in the order they matter here:

- **Proof verification bypass.** Anything that makes the library accept an account,
  a block, a balance or a state that the validators did not sign. Forged proof of
  absence, a pruned branch accepted where a real cell was required, a Merkle proof
  that verifies against the wrong root, or a chain that reaches a block it never
  proved.
- **Signature and validator set.** Accepting a signature set that does not carry
  two thirds of the weight, counting one validator twice, or deriving the set from
  something other than the trusted key block's own configuration.
- **Transport.** Anything that lets a network attacker read, alter or replay a
  session: a degenerate key exchange, a frame accepted after the stream cipher has
  moved, or a handshake that does not bind the peer's key.
- **Freshness.** Passing off an old but genuine chain as current, beyond what the
  documented clock assumption already allows.
- **Panics and resource exhaustion on hostile input.** A parser reachable from
  network bytes that panics, allocates without bound, or does work an attacker can
  amplify. These are denial of service and are in scope.

## What is not in scope

- The two inputs the README documents as trusted: the block the network config
  pins, and the local clock. Their limits are stated rather than defended. A way
  to defeat a check that is supposed to hold despite them is in scope.
- A liteserver refusing to answer, disconnecting, or serving slowly. The library
  is built to be unable to trust a server, not to make one cooperate.
- Vulnerabilities in TON itself, or in a dependency, unless ton-net uses it in a
  way that makes the impact worse than upstream's own advisory describes.

## Disclosure

Fixes are developed in a private advisory and released before details are
published. Anyone who reports a real issue is credited in the advisory and the
release notes unless they ask not to be.

Nothing in this policy is a waiver of anyone's rights, and no legal action will be
pursued over research that stays within it: testing against a self-hosted node or
a public liteserver, without accessing other people's data and without degrading
the network for anyone else.
