"""Kriptografik olarak güçlü rastgele şifre üretimi (secrets modülü)."""
from __future__ import annotations

import secrets
import string


def generate_password(
    length: int = 20,
    *,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
) -> tuple[str, dict]:
    length = max(8, min(128, int(length)))
    pools: list[str] = []
    required: list[str] = []

    if lowercase:
        lo = string.ascii_lowercase
        pools.append(lo)
        required.append(secrets.choice(lo))
    if uppercase:
        up = string.ascii_uppercase
        pools.append(up)
        required.append(secrets.choice(up))
    if digits:
        dg = string.digits
        pools.append(dg)
        required.append(secrets.choice(dg))
    if symbols:
        sym = "!@#$%&*-_=+?"
        pools.append(sym)
        required.append(secrets.choice(sym))

    if not pools:
        lo = string.ascii_lowercase
        pools.append(lo)
        required = [secrets.choice(lo)]

    alphabet = "".join(pools)
    remaining = length - len(required)
    body = [secrets.choice(alphabet) for _ in range(remaining)]
    chars = required + body
    secrets.SystemRandom().shuffle(chars)
    pwd = "".join(chars)

    meta = {
        "uzunluk": length,
        "tahmini_entropi_bit": round(length * 6.5, 1),
        "aciklama": "Karakterler Python secrets modülü ile kriptografik olarak rastgele seçilir. Parolayı ekranda bırakmayın; güvenilir bir şifre yöneticisine kaydedin.",
    }
    return pwd, meta
