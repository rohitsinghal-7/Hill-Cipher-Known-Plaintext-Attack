"""
known_plaintext_attack.py
Cyber Security Lab (7CS4-22) - Mini Project CSL-G04

Attacks on the Hill cipher:
  * Known-plaintext attack (KPA)  - three strategies of increasing power
  * Chosen-plaintext attack (CPA) - using unit-vector blocks
  * Brute-force search            - for comparison (2x2 only)

Encryption is c = K * p (mod 26) for every n-letter block p. The cipher is
LINEAR, so a set of known plaintext/ciphertext block pairs gives a system of
linear equations in the unknown key K.  Writing the n known blocks as the
columns of matrices P and C gives  C = K * P,  hence  K = C * P^-1 (mod 26).
"""

import time
from itertools import combinations

from hill_cipher import (MOD, mat_mul, mat_vec, mat_inverse, is_invertible,
                         mod_inverse, transpose,
                         text_to_nums, split_blocks, nums_to_text,
                         all_invertible_2x2, encrypt)

class AttackError(Exception):
    """Raised when the supplied pairs do not determine the key."""

# Preparing the known pairs
def make_pairs(plaintext, ciphertext, n):
    """Turn a known plaintext/ciphertext string pair into block pairs.
    Only complete n-letter blocks that exist in BOTH strings are used."""
    p = text_to_nums(plaintext)
    c = text_to_nums(ciphertext)
    m = min(len(p), len(c)) // n
    if m == 0:
        raise AttackError("Not enough text: need at least one full block")
    pb = [p[i * n:(i + 1) * n] for i in range(m)]
    cb = [c[i * n:(i + 1) * n] for i in range(m)]
    return list(zip(pb, cb))

def verify_key(K, pairs):
    """True if K maps every known plaintext block to its ciphertext."""
    return all(mat_vec(K, p) == c for p, c in pairs)

# Strategy 1 : direct inversion   K = C * P^-1
def attack_direct(pairs, n, start=0):
    """Place n consecutive known blocks as the COLUMNS of the n x n matrices
    P and C, then K = C * P^-1 (mod 26).  Works only if P is invertible."""
    chosen = pairs[start:start + n]
    if len(chosen) < n:
        raise AttackError(f"Need {n} block pairs, got {len(chosen)}")
    P = transpose([p for p, _ in chosen])     # blocks become columns
    C = transpose([c for _, c in chosen])
    if not is_invertible(P):
        raise AttackError("Plaintext matrix P is not invertible mod 26")
    return mat_mul(C, mat_inverse(P))

# Strategy 2 : search for ANY invertible n-subset of the known blocks
def attack_subset(pairs, n, max_tries=20000):
    tries = 0
    for idx in combinations(range(len(pairs)), n):
        tries += 1
        if tries > max_tries:
            break
        P = transpose([pairs[i][0] for i in idx])
        if not is_invertible(P):
            continue
        C = transpose([pairs[i][1] for i in idx])
        K = mat_mul(C, mat_inverse(P))
        if verify_key(K, pairs):
            return K, idx
    raise AttackError("No invertible subset of plaintext blocks found")

# Strategy 3 : solve modulo 2 and modulo 13, combine with CRT
def solve_mod_prime(pairs, n, p):
    """Gauss-Jordan elimination over the field Z_p.  K p = c is the same as
    p^T K^T = c^T, so solve the row system P K^T = C, then transpose back.
    Returns (K or None, rank)."""
    # augmented rows [ P_row | C_row ]
    rows = [[x % p for x in pb] + [y % p for y in cb] for pb, cb in pairs]
    rank = 0
    for col in range(n):
        piv = next((r for r in range(rank, len(rows))
                    if rows[r][col] % p), None)
        if piv is None:
            continue
        rows[rank], rows[piv] = rows[piv], rows[rank]
        inv = mod_inverse(rows[rank][col], p)
        rows[rank] = [(v * inv) % p for v in rows[rank]]
        for r in range(len(rows)):
            if r != rank and rows[r][col]:
                f = rows[r][col]
                rows[r] = [(a - f * b) % p
                           for a, b in zip(rows[r], rows[rank])]
        rank += 1
    if rank < n:
        return None, rank
    # rows beyond the rank must be all-zero => the pairs are consistent
    for r in range(rank, len(rows)):
        if any(rows[r]):
            raise AttackError("Inconsistent pairs (wrong text?)")
    Kt = [rows[i][n:] for i in range(n)]
    return transpose(Kt), rank

def attack_crt(pairs, n):
    K2, r2 = solve_mod_prime(pairs, n, 2)
    K13, r13 = solve_mod_prime(pairs, n, 13)
    if K2 is None or K13 is None:
        raise AttackError(f"Pairs do not fix the key (rank mod 2 = {r2}, "
                          f"rank mod 13 = {r13}, need {n} for both)")
    # CRT:  K = 13*K2*(13^-1 mod 2) + 2*K13*(2^-1 mod 13)   (mod 26)
    a = 13 * mod_inverse(13, 2)
    b = 2 * mod_inverse(2, 13)
    return [[(a * K2[i][j] + b * K13[i][j]) % MOD for j in range(n)]
            for i in range(n)]

# Driver: try the strategies in order
def recover_key(plaintext, ciphertext, n):
    """Recover the n x n Hill key from a known plaintext/ciphertext pair.
    Returns dict(key, method, seconds, blocks)."""
    pairs = make_pairs(plaintext, ciphertext, n)
    t0 = time.perf_counter()
    K, method = None, None
    for name, fn in (
        ("Direct inversion  K = C P^-1", lambda: attack_direct(pairs, n)),
        ("Block-subset search", lambda: attack_subset(pairs, n)[0]),
        ("Mod-2 / mod-13 solve + CRT", lambda: attack_crt(pairs, n)),
    ):
        try:
            K = fn()
        except AttackError:
            continue
        if K is not None and is_invertible(K) and verify_key(K, pairs):
            method = name
            break
        K = None
    elapsed = time.perf_counter() - t0
    if K is None:
        raise AttackError("Key could not be recovered uniquely from the "
                          "supplied pairs; supply more / different text")
    return {"key": K, "method": method, "seconds": elapsed,
            "blocks": len(pairs)}

# Chosen-plaintext attack
def chosen_plaintext_attack(oracle, n):
    """Query an encryption oracle with unit blocks e_i ("BA", "AB", ...).
    Since K * e_i is the i-th COLUMN of K, the key is read off directly."""
    cols = []
    for i in range(n):
        block = [1 if j == i else 0 for j in range(n)]   # e.g. "BA", "AB"
        cols.append(text_to_nums(oracle(nums_to_text(block))))
    return transpose(cols)

# Brute force (2x2) - for comparison with the KPA
def brute_force_2x2(plaintext, ciphertext):
    """Try every valid 2x2 key until one reproduces the ciphertext.
    Returns (key, keys_tried, seconds)."""
    pairs = make_pairs(plaintext, ciphertext, 2)
    t0 = time.perf_counter()
    tried = 0
    for K in all_invertible_2x2():
        tried += 1
        if verify_key(K, pairs):
            return K, tried, time.perf_counter() - t0
    raise AttackError("Key not found")

def count_consistent_keys_2x2(pairs):
    """How many valid 2x2 keys map every given pair correctly?
    Shows why too few pairs leave the key ambiguous."""
    return sum(1 for K in all_invertible_2x2() if verify_key(K, pairs))
