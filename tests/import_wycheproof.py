#!/usr/bin/env python3
"""Reproduce the offline AES-128 fixtures from a pinned Wycheproof revision.

Run only when refreshing fixtures; differential.py never accesses the network.
The JSON retains upstream test IDs, flags, comments, and expected results.
Only groups outside this library's key/tag-size API are excluded.
"""

import hashlib
import json
from pathlib import Path
import urllib.request


REVISION = "d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9"
BASE = f"https://raw.githubusercontent.com/C2SP/wycheproof/{REVISION}/"
SOURCES = {
    "aes_ccm_test.json": "e713a981df1f261098245f4a1031a34a611df93e0d83f4a6a2c1a13e9ba62d7b",
    "aes_eax_test.json": "70bb17651a8f8a3d9bb4313a63cad0f06ee6300f0c530760144052c09b595e40",
    "aes_gcm_test.json": "985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7",
    "aes_gcm_siv_test.json": "d96e4f8c0db1a5e3b395907120f9d417d599507e7a08a1f60babff09ae276a8d",
}


def fetch(name, digest=None):
    with urllib.request.urlopen(BASE + name, timeout=30) as response:
        data = response.read()
    if digest and hashlib.sha256(data).hexdigest() != digest:
        raise RuntimeError(f"SHA-256 mismatch for {name}")
    return data


def main():
    destination = Path(__file__).resolve().parent / "wycheproof"
    destination.mkdir(exist_ok=True)
    for name, digest in SOURCES.items():
        original = json.loads(fetch("testvectors_v1/" + name, digest))
        groups = [
            group for group in original["testGroups"]
            if group["keySize"] == 128 and (
                group["tagSize"] == 128 or (
                    name == "aes_ccm_test.json" and
                    group["tagSize"] in range(32, 129, 16)
                )
            )
        ]
        selected = sum(len(group["tests"]) for group in groups)
        document = {
            "provenance": {
                "repository": "https://github.com/C2SP/wycheproof",
                "revision": REVISION,
                "path": "testvectors_v1/" + name,
                "sha256": digest,
                "license": "Apache-2.0; see LICENSE",
                "filter": "AES-128; 128-bit tags, or supported CCM tag sizes",
                "upstreamTests": original["numberOfTests"],
                "excludedTests": original["numberOfTests"] - selected,
            },
            "algorithm": original["algorithm"],
            "numberOfTests": selected,
            "notes": original["notes"],
            "testGroups": groups,
        }
        (destination / name).write_text(
            json.dumps(document, indent=2) + "\n", encoding="utf-8"
        )
        print(f"{name}: retained {selected}, excluded {document['provenance']['excludedTests']}")
    (destination / "LICENSE").write_bytes(fetch("LICENSE"))


if __name__ == "__main__":
    main()
