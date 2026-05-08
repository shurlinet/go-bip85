# Upstream Dependencies

Reference implementations and specifications tracked for correctness and updates.

## bipsea (Vector Generation Source)

- **Repo:** https://github.com/akarve/bipsea
- **Version used:** 3.2.0
- **Commit used:** 35386c469971b566b411c5edc505d61a885b5098 (2026-04-27)
- **Used for:** Cross-implementation test vector generation (268 vectors in testdata/vectors.json)
- **Generator script:** tools/gen-vectors/gen.py
- **License:** Apache-2.0
- **Note:** Aneesh Karve (akarve) is both bipsea maintainer AND BIP85 spec co-author
- **Last checked:** 2026-05-09

## BIP85 Specification (bitcoin/bips)

- **Repo:** https://github.com/bitcoin/bips
- **Spec file:** bip-0085.mediawiki
- **Spec version:** v2.0.0
- **Commit checked:** 9fce983a966d214643c8bfed767aa204a80b8a40
- **Last checked:** 2026-05-09
- **Tracked PRs:**
  - #1958 - OPEN - Codex32 application (app 93')
  - #1968 - OPEN - ECC key types (Ed25519, Sr25519)
  - #2040 - OPEN - BIP93: Generalize codex32 format for any hrp and fix typos
  - #2126 - OPEN - Nostr application
  - #2156 - OPEN - Go reference implementation (ours)

## ethankosakovsky/bip85 (Test Pattern Source)

- **Repo:** https://github.com/ethankosakovsky/bip85
- **Commit checked:** 435a0589746c1036735d0a5081167e08abfa7413
- **Used for:** Test patterns adopted (DRNG asymmetric split reads, all-invalid-lengths, 1MB large reads, HEX 32-byte cross-check)
- **License:** MIT
- **Note:** No code embedded. Test approaches and edge case ideas adopted during plan phase.
- **Last checked:** 2026-05-09
