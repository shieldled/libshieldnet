# Security policy

libshieldnet implements an authenticated, encrypted protocol, so we treat a
weakness in it as a security issue. Thank you for reporting one responsibly.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a vulnerability.**
Report it privately through GitHub's private vulnerability reporting: open the
repository's **Security** tab and choose **Report a vulnerability**. Only the
maintainers see the report, and we can discuss it, prepare a fix and publish an
advisory there before the details become public.

Please include:

- the affected version (release tag or commit) and the package or file;
- what an attacker can do, and from where (on the network without the PSK, as
  an admitted peer, as a device answering a client, ...);
- the steps, input or proof of concept that reproduces it, such as datagrams
  in hex, a test case or a small program;
- the impact as you understand it, and any fix you suggest.

We aim to acknowledge a report within a few working days, to keep you informed
while we investigate and fix it, and to credit you in the advisory unless you
prefer otherwise. Please give us a reasonable time to release a fix before
disclosing the issue publicly.

## Scope

In scope: the code in this repository, in particular

- the transport: datagram classification and source checks, the encrypted
  envelope, replay protection, KCP framing and the send and receive bounds;
- admission and cryptography: the admission exchange, key derivation, MACs,
  AEAD use, nonce and key handling, and key material left in memory;
- the codecs: parsing and encoding of control messages, message-layer frames,
  decompression, and the application payloads;
- discovery, where the library has it: parsing of mDNS answers and the
  records they carry.

Out of scope:

- weaknesses in the protocol itself, which are reported to
  [shieldnet-protocol](https://github.com/shieldled/shieldnet-protocol) (report
  them there the same way);
- vulnerabilities in dependencies, unless this repository uses them unsafely
  (report those upstream);
- options of the example programs that are documented as development-only and
  unsafe for deployment, such as turning off the same-host source check;
- denial of service by flooding the network beyond what the protocol bounds;
- attacks that need the PSK, or a device's `k_dev` against that same device
  (a `k_dev` that opens any other device is in scope);
- deployments that ignore documented requirements, such as a device holding
  the PSK.

## Dependencies and SBOM

Every change, every tag and a weekly run produce a CycloneDX SBOM (`ci/sbom.py`,
the `sbom` artifact of the Security workflow) of the library and the third-party
code it builds with: LZ4 and KCP (vendored) and libsodium (linked; the version CI builds). Grype scans it for known vulnerabilities, and a
high or critical finding fails the run.

## Supported versions

Security fixes go into the latest minor release. Before 1.0, a fix may need an
upgrade to that release rather than a patch to an older one.
