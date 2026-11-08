from __future__ import annotations
import base64

def xor_decrypt(enc: str, key: str) -> str:
    raw = base64.b64decode(enc)
    return "".join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(raw))