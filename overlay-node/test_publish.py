#!/usr/bin/env python3
"""Multi-node DHT mesh test for tsm-overlay-node.

Generates an Ed25519 keypair, signs a self-certifying name record using the
EXACT canonical bytes the Rust data plane (`overlay::name::signing_bytes`) and
the Go overlay-node (`signingBytes`) both use, POSTs it to node A's `/publish`
(DHT put), then GETs node B's `/resolve/<name>` (DHT get) to prove the record
propagated across the libp2p Kademlia mesh — no central authority involved.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NAME = os.environ.get("NAME", "mesh-demo.tsm")
ENDPOINT = os.environ.get("ENDPOINT", "tsm:welcome")
SEQ = int(os.environ.get("SEQ", "1"))
A = os.environ.get("NODE_A", "http://overlay-a:7700")
B = os.environ.get("NODE_B", "http://overlay-b:7700")


def signing_bytes(name: str, pubkey: bytes, endpoint: str, seq: int) -> bytes:
    """Mirror of overlay::name::signing_bytes (Rust) / signingBytes (Go)."""
    return (
        b"tsm-overlay-name-v1\x00"
        + name.encode()
        + b"\x00"
        + pubkey
        + b"\x00"
        + endpoint.encode()
        + b"\x00"
        + struct.pack(">Q", seq)
    )


def main() -> int:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key().public_bytes_raw()
    sig = sk.sign(signing_bytes(NAME, pk, ENDPOINT, SEQ))

    rec = {
        "name": NAME,
        "pubkey": pk.hex(),
        "endpoint": ENDPOINT,
        "sequence": SEQ,
        "signature": sig.hex(),
    }
    print("RECORD:", json.dumps(rec))

    # Publish on node A → DHT put across the mesh.
    req = urllib.request.Request(
        f"{A}/publish",
        data=json.dumps(rec).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        out = urllib.request.urlopen(req, timeout=30).read().decode()
        print("PUBLISH (A):", out)
    except urllib.error.HTTPError as e:
        print("PUBLISH ERR:", e.code, e.read().decode())
        return 1

    # Resolve via node B → DHT get; the record must have propagated.
    time.sleep(2)
    for attempt in range(1, 4):
        try:
            out = urllib.request.urlopen(f"{B}/resolve/{NAME}", timeout=30).read().decode()
            print(f"RESOLVE (B, attempt {attempt}):", out)
            return 0
        except urllib.error.HTTPError as e:
            print(f"RESOLVE ERR (attempt {attempt}):", e.code, e.read().decode())
            if attempt == 3:
                return 1
            time.sleep(3)
    return 1


if __name__ == "__main__":
    sys.exit(main())
