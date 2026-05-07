#!/usr/bin/env python3
"""
BIP85 cross-implementation test vector generator for go-bip85.

Generates deterministic test vectors using bipsea (Python, gold standard)
covering all 9 BIP85 applications across 5 master keys.

Requirements:
    pip install bipsea (or: source /tmp/bipsea-venv/bin/activate)

Usage:
    BIPSEA_SRC=/tmp/bipsea/src python3 tools/gen-vectors/gen.py

    If BIPSEA_SRC is not set, falls back to /tmp/bipsea/src.

Output: testdata/vectors.json, testdata/regression.json
"""

import json
import os
import sys

bipsea_src = os.environ.get("BIPSEA_SRC", "/tmp/bipsea/src")
if bipsea_src not in sys.path:
    sys.path.insert(0, bipsea_src)

from hashlib import pbkdf2_hmac
from unicodedata import normalize

from bipsea.bip32 import to_master_key
from bipsea.bip32types import parse_ext_key
from bipsea.bip85 import apply_85, derive, do_rolls, to_entropy
from bipsea.drng import DRNG


# ---- Constants ----

SPEC_XPRV = (
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
)

# Standard test mnemonics (well-known, used by BIP39/TREZOR test suites)
MNEMONIC_12 = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
MNEMONIC_24 = (
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
)
# Leading-zero stress key: derived child at m/83696968'/0'/0' has private key
# starting with 0x00 (tests big.Int.Bytes() leading-zero preservation, F37).
MNEMONIC_LEADING_ZERO = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon album about"
)


# ---- Helper Functions ----


def make_master(mnemonic, mainnet=True):
    seed = pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), b"mnemonic", 2048)
    return to_master_key(seed, mainnet=mainnet, private=True)


def build_masters():
    """Construct all master keys. Called once from main(), not at import time."""
    masters = [
        {
            "id": "spec",
            "xprv": SPEC_XPRV,
            "source": "BIP85 spec v2.0.0",
            "key": parse_ext_key(SPEC_XPRV),
        },
        {
            "id": "leading_zero",
            "xprv": None,
            "source": (
                "BIP39 mnemonic (leading-zero derived key at m/83696968'/0'/0'): "
                + MNEMONIC_LEADING_ZERO
            ),
            "mnemonic": MNEMONIC_LEADING_ZERO,
            "key": make_master(MNEMONIC_LEADING_ZERO),
        },
        {
            "id": "12word",
            "xprv": None,
            "source": f"BIP39 mnemonic: {MNEMONIC_12}",
            "mnemonic": MNEMONIC_12,
            "key": make_master(MNEMONIC_12),
        },
        {
            "id": "24word",
            "xprv": None,
            "source": f"BIP39 mnemonic: {MNEMONIC_24}",
            "mnemonic": MNEMONIC_24,
            "key": make_master(MNEMONIC_24),
        },
        {
            "id": "testnet",
            "xprv": None,
            "source": f"BIP39 mnemonic (testnet): {MNEMONIC_12}",
            "mnemonic": MNEMONIC_12,
            "key": make_master(MNEMONIC_12, mainnet=False),
        },
    ]
    for m in masters:
        if m["xprv"] is None:
            m["xprv"] = str(m["key"])

    # Verify leading-zero property holds
    lz = next(m for m in masters if m["id"] == "leading_zero")
    child = derive(lz["key"], "m/83696968'/0'/0'")
    raw_key = child.data[1:]
    assert raw_key[0] == 0, (
        f"leading_zero master: derived key does NOT start with 0x00: "
        f"0x{raw_key[0]:02x}. Mnemonic needs updating."
    )

    return masters


def derive_core(master_key, path):
    """Derive child key and extract entropy for a given BIP85 path."""
    child = derive(master_key, path)
    raw_key = child.data[1:]
    entropy = to_entropy(raw_key)
    return raw_key.hex(), entropy.hex()


def derive_app_vector(master_key, path, app_name, params):
    """Derive a BIP85 application and return a complete vector dict.

    Always includes the full 64-byte HMAC entropy (entropy_hex, 128 hex chars)
    AND the application-specific truncated entropy (app_entropy_hex, varies).
    This lets Go tests verify both the derivation pipeline and the app truncation.
    """
    child = derive(master_key, path)
    raw_key = child.data[1:]
    full_entropy = to_entropy(raw_key)
    result = apply_85(child, path)
    output = str(result["application"])
    # BIP39 wordlists are NFC in the official Bitcoin repo. bipsea may output
    # NFD (decomposed) on some platforms (macOS NFD filenames). Normalize to
    # NFC so Go tests do a simple string comparison against NFC wordlists.
    if app_name == "bip39":
        output = normalize("NFC", output)
    return {
        "app": app_name,
        "path": path,
        "derived_key": "",
        "entropy_hex": full_entropy.hex(),
        "app_entropy_hex": result["entropy"].hex(),
        "output": output,
        "params": params,
        "source": "bipsea",
        "note": "",
    }


def derive_drng(master_key, path, num_bytes):
    """Derive DRNG output via single read."""
    child = derive(master_key, path)
    entropy = to_entropy(child.data[1:])
    drng = DRNG(entropy)
    return entropy.hex(), drng.read(num_bytes).hex()


def derive_drng_split(master_key, path, chunks):
    """Derive DRNG output via split reads, return concatenated hex."""
    child = derive(master_key, path)
    entropy = to_entropy(child.data[1:])
    drng = DRNG(entropy)
    parts = [drng.read(n).hex() for n in chunks]
    return entropy.hex(), "".join(parts)


# ---- Vector Generation ----


def generate_vectors(masters):
    all_vectors = []

    for m in masters:
        master_key = m["key"]
        master_id = m["id"]
        xprv_str = m["xprv"]
        vectors = []

        # -- Core HMAC (2 per master) --
        for idx in [0, 1]:
            path = f"m/83696968'/0'/{idx}'"
            dk, ent = derive_core(master_key, path)
            vectors.append({
                "app": "core",
                "path": path,
                "derived_key": dk,
                "entropy_hex": ent,
                "app_entropy_hex": "",
                "output": "",
                "params": {"index": idx},
                "source": "bipsea",
                "note": "",
            })

        # -- DRNG: single read 80 bytes --
        drng_path = "m/83696968'/0'/0'"
        ent_single, drng_out = derive_drng(master_key, drng_path, 80)
        vectors.append({
            "app": "drng",
            "path": drng_path,
            "derived_key": "",
            "entropy_hex": ent_single,
            "app_entropy_hex": "",
            "output": drng_out,
            "params": {"read_bytes": 80},
            "source": "bipsea",
            "note": "",
        })

        # -- DRNG: split reads 20+20+20+20 = 80 --
        ent_split, drng_split = derive_drng_split(master_key, drng_path, [20, 20, 20, 20])
        assert drng_out == drng_split, (
            f"DRNG determinism failure for {master_id}: "
            f"single-read(80) != split-read(20x4)"
        )
        vectors.append({
            "app": "drng_split",
            "path": drng_path,
            "derived_key": "",
            "entropy_hex": ent_split,
            "app_entropy_hex": "",
            "output": drng_split,
            "params": {"chunks": [20, 20, 20, 20]},
            "source": "bipsea",
            "note": "",
        })

        # -- DRNG: split reads 1 byte x 80 --
        ent_byte, drng_byte = derive_drng_split(master_key, drng_path, [1] * 80)
        assert drng_out == drng_byte, (
            f"DRNG determinism failure for {master_id}: "
            f"single-read(80) != split-read(1x80)"
        )
        vectors.append({
            "app": "drng_split",
            "path": drng_path,
            "derived_key": "",
            "entropy_hex": ent_byte,
            "app_entropy_hex": "",
            "output": drng_byte,
            "params": {"chunks": [1] * 80},
            "source": "bipsea",
            "note": "",
        })

        # -- BIP39 English: 12, 15, 18, 21, 24 words x indexes 0, 1 --
        for words in [12, 15, 18, 21, 24]:
            for idx in [0, 1]:
                path = f"m/83696968'/39'/0'/{words}'/{idx}'"
                vectors.append(derive_app_vector(
                    master_key, path, "bip39",
                    {"language": 0, "words": words, "index": idx},
                ))

        # -- BIP39 Japanese: 12, 24 words --
        for words in [12, 24]:
            path = f"m/83696968'/39'/1'/{words}'/0'"
            vectors.append(derive_app_vector(
                master_key, path, "bip39",
                {"language": 1, "words": words, "index": 0},
            ))

        # -- BIP39 all other 8 languages: 12 words each --
        for lang_code in [2, 3, 4, 5, 6, 7, 8, 9]:
            path = f"m/83696968'/39'/{lang_code}'/12'/0'"
            vectors.append(derive_app_vector(
                master_key, path, "bip39",
                {"language": lang_code, "words": 12, "index": 0},
            ))

        # -- WIF: indexes 0, 1, 100 --
        for idx in [0, 1, 100]:
            path = f"m/83696968'/2'/{idx}'"
            vectors.append(derive_app_vector(
                master_key, path, "wif", {"index": idx},
            ))

        # -- XPRV: indexes 0, 1, 100 --
        for idx in [0, 1, 100]:
            path = f"m/83696968'/32'/{idx}'"
            vectors.append(derive_app_vector(
                master_key, path, "xprv", {"index": idx},
            ))

        # -- HEX: lengths 16, 32, 48, 64 x indexes 0, 1 --
        for length in [16, 32, 48, 64]:
            for idx in [0, 1]:
                path = f"m/83696968'/128169'/{length}'/{idx}'"
                vectors.append(derive_app_vector(
                    master_key, path, "hex",
                    {"num_bytes": length, "index": idx},
                ))

        # -- HEX: agent-scale index 10000 (typical batch derivation) --
        path = f"m/83696968'/128169'/32'/10000'"
        vectors.append(derive_app_vector(
            master_key, path, "hex",
            {"num_bytes": 32, "index": 10000},
        ))

        # -- HEX: max index (2^31-1) stress test (F4, F105, F116) --
        max_idx = 2147483647
        path = f"m/83696968'/128169'/32'/{max_idx}'"
        vectors.append(derive_app_vector(
            master_key, path, "hex",
            {"num_bytes": 32, "index": max_idx},
        ))

        # -- PWD BASE64: lengths 20, 21 (spec), 40, 86 --
        for length in [20, 21, 40, 86]:
            path = f"m/83696968'/707764'/{length}'/0'"
            vectors.append(derive_app_vector(
                master_key, path, "base64",
                {"pwd_len": length, "index": 0},
            ))

        # -- PWD BASE85: lengths 10, 12 (spec), 40, 80 --
        for length in [10, 12, 40, 80]:
            path = f"m/83696968'/707785'/{length}'/0'"
            vectors.append(derive_app_vector(
                master_key, path, "base85",
                {"pwd_len": length, "index": 0},
            ))

        # -- DICE: 6 sides x 10 rolls, indexes 0, 1 --
        for idx in [0, 1]:
            path = f"m/83696968'/89101'/6'/10'/{idx}'"
            child = derive(master_key, path)
            ent_bytes = to_entropy(child.data[1:])
            rolls = do_rolls(ent_bytes, 6, 10, idx)
            vectors.append({
                "app": "dice",
                "path": path,
                "derived_key": "",
                "entropy_hex": ent_bytes.hex(),
                "app_entropy_hex": "",
                "output": rolls,
                "params": {"sides": 6, "rolls": 10, "index": idx},
                "source": "bipsea",
                "note": "",
            })

        # -- DICE: 2 sides (coin flip) x 20 rolls --
        path = "m/83696968'/89101'/2'/20'/0'"
        child = derive(master_key, path)
        ent_bytes = to_entropy(child.data[1:])
        rolls = do_rolls(ent_bytes, 2, 20, 0)
        vectors.append({
            "app": "dice",
            "path": path,
            "derived_key": "",
            "entropy_hex": ent_bytes.hex(),
            "app_entropy_hex": "",
            "output": rolls,
            "params": {"sides": 2, "rolls": 20, "index": 0},
            "source": "bipsea",
            "note": "",
        })

        # -- DICE: 100 sides x 10 rolls --
        path = "m/83696968'/89101'/100'/10'/0'"
        child = derive(master_key, path)
        ent_bytes = to_entropy(child.data[1:])
        rolls = do_rolls(ent_bytes, 100, 10, 0)
        vectors.append({
            "app": "dice",
            "path": path,
            "derived_key": "",
            "entropy_hex": ent_bytes.hex(),
            "app_entropy_hex": "",
            "output": rolls,
            "params": {"sides": 100, "rolls": 10, "index": 0},
            "source": "bipsea",
            "note": "",
        })

        # Annotate testnet XPRV vectors: bipsea always emits xprv even for
        # testnet input. BIP85 spec says testnet support is optional ("MAY").
        # The Go implementation should detect testnet input and emit tprv.
        if master_id == "testnet":
            for v in vectors:
                if v["app"] == "xprv":
                    v["note"] = (
                        "bipsea emits xprv for testnet input (spec says MAY support testnet). "
                        "Go impl should emit tprv when input is tprv."
                    )

        all_vectors.append({
            "master_id": master_id,
            "master_xprv": xprv_str,
            "master_source": m["source"],
            "vector_count": len(vectors),
            "vectors": vectors,
        })

    # ---- Ethankosakovsky extra vectors (spec master key only) ----
    ethan_vectors = []
    spec_m = next(m for m in masters if m["id"] == "spec")
    spec_key = spec_m["key"]
    spec_xprv_str = spec_m["xprv"]
    path_0_0 = "m/83696968'/0'/0'"

    # HEX 32-byte at index 0 - generated with cross-check against hardcoded
    v_h32 = derive_app_vector(
        spec_key, "m/83696968'/128169'/32'/0'", "hex",
        {"num_bytes": 32, "index": 0},
    )
    assert v_h32["output"] == "ea3ceb0b02ee8e587779c63f4b7b3a21e950a213f1ec53cab608d13e8796e6dc", (
        f"ethankosakovsky HEX 32 cross-check failed: {v_h32['output']}"
    )
    v_h32["source"] = "ethankosakovsky"
    ethan_vectors.append(v_h32)

    # HEX 64-byte at index 1234 - generated with cross-check
    v_h64 = derive_app_vector(
        spec_key, "m/83696968'/128169'/64'/1234'", "hex",
        {"num_bytes": 64, "index": 1234},
    )
    assert v_h64["output"] == (
        "61d3c182f7388268463ef327c454a10bc01b3992fa9d2ee1b3891a6b487a5248"
        "793e61271066be53660d24e8cb76ff0cfdd0e84e478845d797324c195df9ab8e"
    ), f"ethankosakovsky HEX 64/1234 cross-check failed: {v_h64['output']}"
    v_h64["source"] = "ethankosakovsky"
    ethan_vectors.append(v_h64)

    # DRNG sequential reads from same stream
    child = derive(spec_key, path_0_0)
    ent_bytes = to_entropy(child.data[1:])

    # Stream 1: 50 + 100 + 150
    drng1 = DRNG(ent_bytes)
    reads_1 = [(50, 0), (100, 50), (150, 150)]
    for read_bytes, offset in reads_1:
        out = drng1.read(read_bytes).hex()
        ethan_vectors.append({
            "app": "drng_sequential",
            "path": path_0_0,
            "derived_key": "",
            "entropy_hex": ent_bytes.hex(),
            "app_entropy_hex": "",
            "output": out,
            "params": {"read_bytes": read_bytes, "cumulative_offset": offset},
            "source": "ethankosakovsky",
            "note": "",
        })

    # Stream 2: 80 + 25
    drng2 = DRNG(ent_bytes)
    for read_bytes, offset in [(80, 0), (25, 80)]:
        out = drng2.read(read_bytes).hex()
        ethan_vectors.append({
            "app": "drng_sequential",
            "path": path_0_0,
            "derived_key": "",
            "entropy_hex": ent_bytes.hex(),
            "app_entropy_hex": "",
            "output": out,
            "params": {"read_bytes": read_bytes, "cumulative_offset": offset},
            "source": "ethankosakovsky",
            "note": "",
        })

    # Stream 3: 20 + 25
    drng3 = DRNG(ent_bytes)
    for read_bytes, offset in [(20, 0), (25, 20)]:
        out = drng3.read(read_bytes).hex()
        ethan_vectors.append({
            "app": "drng_sequential",
            "path": path_0_0,
            "derived_key": "",
            "entropy_hex": ent_bytes.hex(),
            "app_entropy_hex": "",
            "output": out,
            "params": {"read_bytes": read_bytes, "cumulative_offset": offset},
            "source": "ethankosakovsky",
            "note": "",
        })

    all_vectors.append({
        "master_id": "ethankosakovsky",
        "master_xprv": spec_xprv_str,
        "master_source": "ethankosakovsky/bip85 test suite extra vectors (spec master key)",
        "vector_count": len(ethan_vectors),
        "vectors": ethan_vectors,
    })

    return all_vectors


def select_regression_vectors(all_vectors):
    """Select 21 vectors for hardcoded regression set covering edge cases."""
    regression = []

    def find(master_id, app, path_contains=None, idx=None):
        for group in all_vectors:
            if group["master_id"] != master_id:
                continue
            for v in group["vectors"]:
                if v["app"] != app:
                    continue
                if path_contains and path_contains not in v["path"]:
                    continue
                if idx is not None and v.get("params", {}).get("index") != idx:
                    continue
                return {"master_id": master_id, "master_xprv": group["master_xprv"], **v}
        return None

    # 1-2: Spec core HMAC (foundation of everything)
    regression.append(find("spec", "core", idx=0))
    regression.append(find("spec", "core", idx=1))

    # 3-5: All three spec BIP39 word counts (12/18/24)
    regression.append(find("spec", "bip39", path_contains="39'/0'/12'/0'"))
    regression.append(find("spec", "bip39", path_contains="39'/0'/18'/0'"))
    regression.append(find("spec", "bip39", path_contains="39'/0'/24'/0'"))

    # 6: Spec WIF
    regression.append(find("spec", "wif", idx=0))

    # 7: Spec XPRV
    regression.append(find("spec", "xprv", idx=0))

    # 8: Spec HEX 64 bytes
    regression.append(find("spec", "hex", path_contains="128169'/64'/0'"))

    # 9: Spec BASE64 (pwd_len=21)
    regression.append(find("spec", "base64", path_contains="/21'/0'"))

    # 10: Spec BASE85 (pwd_len=12)
    regression.append(find("spec", "base85", path_contains="/12'/0'"))

    # 11: Spec DICE 6 sides
    regression.append(find("spec", "dice", path_contains="89101'/6'/10'/0'"))

    # 12: Spec DRNG 80 bytes
    regression.append(find("spec", "drng"))

    # 13: Japanese BIP39 (ideographic space separator)
    regression.append(find("spec", "bip39", path_contains="39'/1'/12'/0'"))

    # 14: Leading-zero derived key (F37 big.Int stress test)
    regression.append(find("leading_zero", "core", idx=0))

    # 15-16: BIP39 15/21 words (no spec vectors for these)
    regression.append(find("12word", "bip39", path_contains="39'/0'/15'/0'"))
    regression.append(find("12word", "bip39", path_contains="39'/0'/21'/0'"))

    # 17: HEX minimum length 16
    regression.append(find("spec", "hex", path_contains="128169'/16'/0'"))

    # 18: Max index 2^31-1 (F4, F105, F116)
    regression.append(find("spec", "hex", idx=2147483647))

    # 19: DICE coin flip (2 sides)
    regression.append(find("spec", "dice", path_contains="89101'/2'/20'/0'"))

    # 20: Testnet XPRV (tprv input)
    regression.append(find("testnet", "xprv", idx=0))

    # 21: DRNG split-read determinism (20+20+20+20 == 80)
    regression.append(find("spec", "drng_split", path_contains="0'/0'"))

    labeled = []
    for i, r in enumerate(regression):
        if r is None:
            print(f"WARNING: regression vector {i + 1} not found!", file=sys.stderr)
            continue
        r["regression_id"] = i + 1
        labeled.append(r)

    return labeled


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(os.path.dirname(script_dir))
    testdata_dir = os.path.join(repo_root, "testdata")
    os.makedirs(testdata_dir, exist_ok=True)

    print("Building master keys...")
    masters = build_masters()

    print("Generating BIP85 cross-implementation test vectors...")
    all_vectors = generate_vectors(masters)

    total = sum(g["vector_count"] for g in all_vectors)
    print(f"Generated {total} vectors across {len(all_vectors)} master key groups")
    for g in all_vectors:
        print(f"  {g['master_id']}: {g['vector_count']} vectors")

    vectors_path = os.path.join(testdata_dir, "vectors.json")
    with open(vectors_path, "w") as f:
        json.dump(
            {
                "generator": "go-bip85/tools/gen-vectors/gen.py",
                "reference_impl": "bipsea 3.2.0 (Python)",
                "spec_version": "BIP85 v2.0.0",
                "master_keys": all_vectors,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"Wrote {vectors_path}")

    print("Selecting regression vectors...")
    regression = select_regression_vectors(all_vectors)
    regression_path = os.path.join(testdata_dir, "regression.json")
    with open(regression_path, "w") as f:
        json.dump(
            {
                "generator": "go-bip85/tools/gen-vectors/gen.py",
                "reference_impl": "bipsea 3.2.0 (Python)",
                "spec_version": "BIP85 v2.0.0",
                "description": (
                    "Hardcoded regression vectors covering edge cases. "
                    "These are compiled into Go test code and survive even "
                    "if vectors.json is corrupted."
                ),
                "vectors": regression,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    print(f"Wrote {regression_path} ({len(regression)} vectors)")


if __name__ == "__main__":
    main()
