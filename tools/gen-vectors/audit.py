#!/usr/bin/env python3
"""Round 2 audit: validate all generated vectors."""
import json
import re
import sys
import os

repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

with open(os.path.join(repo, "testdata/vectors.json")) as f:
    data = json.load(f)
with open(os.path.join(repo, "testdata/regression.json")) as f:
    reg = json.load(f)

issues = []
required = {"app", "path", "derived_key", "entropy_hex", "app_entropy_hex", "output", "params", "source", "note"}
hex_re = re.compile(r"^[0-9a-f]*$")

for g in data["master_keys"]:
    mid = g["master_id"]
    for i, v in enumerate(g["vectors"]):
        tag = f"{mid} {v['app']} {v['path']}"

        # Schema: all required fields present
        missing = required - set(v.keys())
        if missing:
            issues.append(f"{tag}: missing fields {missing}")

        # entropy_hex always 128 hex chars (64 bytes HMAC output)
        ent = v["entropy_hex"]
        if ent and len(ent) != 128:
            issues.append(f"{tag}: entropy_hex len={len(ent)} (expected 128)")

        # All hex fields are valid hex
        for fld in ["derived_key", "entropy_hex", "app_entropy_hex"]:
            val = v.get(fld, "")
            if val and not hex_re.match(val):
                issues.append(f"{tag}: {fld} contains non-hex chars")

        # Core: derived_key is 64 hex chars, output is empty
        if v["app"] == "core":
            if len(v["derived_key"]) != 64:
                issues.append(f"{tag}: derived_key len={len(v['derived_key'])}")
            if v["output"] != "":
                issues.append(f"{tag}: output should be empty")

        # HEX: output length matches num_bytes
        if v["app"] == "hex":
            expected_len = v["params"]["num_bytes"] * 2
            if len(v["output"]) != expected_len:
                issues.append(f"{tag}: output len={len(v['output'])} expected={expected_len}")

        # BASE64: output length matches pwd_len
        if v["app"] == "base64":
            if len(v["output"]) != v["params"]["pwd_len"]:
                issues.append(f"{tag}: output len={len(v['output'])} expected={v['params']['pwd_len']}")

        # BASE85: output length matches pwd_len
        if v["app"] == "base85":
            if len(v["output"]) != v["params"]["pwd_len"]:
                issues.append(f"{tag}: output len={len(v['output'])} expected={v['params']['pwd_len']}")

        # WIF: prefix K/L (mainnet) or c (testnet)
        if v["app"] == "wif":
            first = v["output"][0]
            if mid == "testnet" and first != "c":
                issues.append(f"{tag}: WIF prefix '{first}' expected 'c' (testnet)")
            elif mid != "testnet" and first not in ("K", "L"):
                issues.append(f"{tag}: WIF prefix '{first}' expected K or L")

        # XPRV: prefix xprv (mainnet) or tprv (testnet)
        # Note: bipsea always emits xprv even for testnet input (spec says
        # testnet support is optional: "MAY support Testnet"). Our Go impl
        # WILL handle this correctly, but bipsea-generated vectors use xprv.
        if v["app"] == "xprv":
            prefix = v["output"][:4]
            if mid != "testnet" and prefix != "xprv":
                issues.append(f"{tag}: XPRV prefix '{prefix}' expected 'xprv'")

        # DICE: roll count + value range
        if v["app"] == "dice":
            rolls = v["output"].split(",")
            if len(rolls) != v["params"]["rolls"]:
                issues.append(f"{tag}: roll count={len(rolls)} expected={v['params']['rolls']}")
            for r in rolls:
                if int(r) < 0 or int(r) >= v["params"]["sides"]:
                    issues.append(f"{tag}: roll value {r} out of [0,{v['params']['sides']-1}]")

        # BIP39: word count
        if v["app"] == "bip39":
            words = v["output"].split(" ")
            if len(words) != v["params"]["words"]:
                issues.append(f"{tag}: word count={len(words)} expected={v['params']['words']}")

        # DRNG/DRNG_SEQUENTIAL: output hex length
        if v["app"] in ("drng", "drng_sequential"):
            expected_len = v["params"]["read_bytes"] * 2
            if len(v["output"]) != expected_len:
                issues.append(f"{tag}: output len={len(v['output'])} expected={expected_len}")

        # DRNG_SPLIT: output hex length = sum(chunks)*2
        if v["app"] == "drng_split":
            expected_len = sum(v["params"]["chunks"]) * 2
            if len(v["output"]) != expected_len:
                issues.append(f"{tag}: output len={len(v['output'])} expected={expected_len}")

        # All paths start with m/83696968'
        if not v["path"].startswith("m/83696968'"):
            issues.append(f"{tag}: bad path prefix")

# Cross-check: DRNG single == split for each master
for g in data["master_keys"]:
    if g["master_id"] == "ethankosakovsky":
        continue
    single = next((v["output"] for v in g["vectors"] if v["app"] == "drng"), None)
    split4 = next(
        (v["output"] for v in g["vectors"]
         if v["app"] == "drng_split" and v["params"].get("chunks") == [20, 20, 20, 20]),
        None,
    )
    if single and split4 and single != split4:
        issues.append(f"{g['master_id']}: drng single(80) != split(20x4)")

# Leading-zero key verification
lz = next(g for g in data["master_keys"] if g["master_id"] == "leading_zero")
lzc = next(v for v in lz["vectors"] if v["app"] == "core" and v["params"]["index"] == 0)
if not lzc["derived_key"].startswith("00"):
    issues.append(f"leading_zero derived_key starts with {lzc['derived_key'][:4]} not 00")

# Max-index vector exists
max_found = False
for g in data["master_keys"]:
    for v in g["vectors"]:
        if v.get("params", {}).get("index") == 2147483647:
            max_found = True
            break
if not max_found:
    issues.append("no max-index (2^31-1) vector found")

# Regression completeness
if len(reg["vectors"]) != 21:
    issues.append(f"regression count={len(reg['vectors'])} expected=21")
for rv in reg["vectors"]:
    for fld in ["regression_id", "master_id", "master_xprv", "app", "path", "entropy_hex", "output"]:
        if fld not in rv:
            issues.append(f"regression vec missing '{fld}'")
# No duplicates
seen = set()
for rv in reg["vectors"]:
    key = (rv["master_id"], rv["path"], rv["app"])
    if key in seen:
        issues.append(f"duplicate regression: {key}")
    seen.add(key)

# Testnet master_xprv starts with tprv
tn = next(g for g in data["master_keys"] if g["master_id"] == "testnet")
if not tn["master_xprv"].startswith("tprv"):
    issues.append(f"testnet master_xprv prefix: {tn['master_xprv'][:4]}")

# Report
if issues:
    print(f"FOUND {len(issues)} ISSUES:")
    for iss in issues:
        print(f"  - {iss}")
    sys.exit(1)
else:
    total = sum(g["vector_count"] for g in data["master_keys"])
    print(f"ROUND 2 AUDIT: ZERO ISSUES")
    print(f"  Vectors: {total} | Regression: {len(reg['vectors'])} | Groups: {len(data['master_keys'])}")
    print(f"  Checks: schema, hex validity, output lengths, prefixes, dice range,")
    print(f"          word counts, DRNG lengths, path prefixes, cross-checks,")
    print(f"          leading-zero, max-index, regression completeness, no duplicates")
