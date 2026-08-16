"""Educational demonstration: compare fast SHA-256 guesses with bcrypt guesses.

Run only against the synthetic password below. Never target third-party systems.
"""

from __future__ import annotations

import hashlib
import itertools
import string
import time

try:
    import bcrypt
except ImportError as exc:
    raise SystemExit("Install dependencies first: pip install -r requirements.txt") from exc

TARGET = "a9Z!"
ALPHABET = string.ascii_letters + string.digits + "!"


def candidates(max_length: int = 4):
    for length in range(1, max_length + 1):
        for chars in itertools.product(ALPHABET, repeat=length):
            yield "".join(chars)


def sha_demo() -> tuple[str | None, int, float]:
    target_hash = hashlib.sha256(TARGET.encode()).digest()
    start = time.perf_counter()
    for attempts, candidate in enumerate(candidates(), 1):
        if hashlib.sha256(candidate.encode()).digest() == target_hash:
            return candidate, attempts, time.perf_counter() - start
    return None, attempts, time.perf_counter() - start


def bcrypt_demo(limit: int = 1000) -> tuple[int, float]:
    target_hash = bcrypt.hashpw(TARGET.encode(), bcrypt.gensalt(rounds=12))
    start = time.perf_counter()
    attempts = 0
    for attempts, candidate in enumerate(candidates(), 1):
        bcrypt.checkpw(candidate.encode(), target_hash)
        if attempts >= limit:
            break
    return attempts, time.perf_counter() - start


if __name__ == "__main__":
    found, attempts, elapsed = sha_demo()
    print(f"SHA-256: found={found!r}, attempts={attempts}, duration={elapsed:.3f}s")
    attempts, elapsed = bcrypt_demo()
    print(f"bcrypt: {attempts} controlled guesses took {elapsed:.3f}s")
