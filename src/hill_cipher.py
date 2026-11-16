"""
hill_cipher.py
Cyber Security Lab (7CS4-22) - Mini Project CSL-G04
Hill Cipher with Known-Plaintext Attack

Core Hill cipher library written in pure Python (no external packages).
All matrix arithmetic is done modulo 26 using the column-vector convention

        C = K * P  (mod 26)

where P and C are n x 1 column vectors (one n-letter block) and K is the
n x n key matrix (filled row by row from the key word).
Decryption uses  P = K^-1 * C  (mod 26).
"""

from math import gcd
from itertools import product

MOD = 26

# Number-theory helpers
def egcd(a, b):
    """Extended Euclid: returns (g, x, y) with a*x + b*y = g = gcd(a, b)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def mod_inverse(a, m=MOD):
    """Multiplicative inverse of a modulo m; raises ValueError if none."""
    a %= m
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse modulo {m} (gcd = {g})")
    return x % m

# Matrix helpers (plain lists of lists)
def mat_mul(A, B, m=MOD):
    """Matrix product (A x B) mod m."""
    rows, inner, cols = len(A), len(B), len(B[0])
    return [[sum(A[i][k] * B[k][j] for k in range(inner)) % m
             for j in range(cols)] for i in range(rows)]

def mat_vec(K, v, m=MOD):
    """Matrix K times column vector v (given as a flat list) mod m."""
    return [sum(K[i][j] * v[j] for j in range(len(v))) % m
            for i in range(len(K))]

def transpose(M):
    return [list(r) for r in zip(*M)]

def identity(n):
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]

def minor(M, i, j):
    """Matrix M with row i and column j removed."""
    return [row[:j] + row[j + 1:] for k, row in enumerate(M) if k != i]

def determinant(M, m=None):
    """Determinant by cofactor expansion along the first row.
    If m is given the result is reduced modulo m."""
    n = len(M)
    if n == 1:
        d = M[0][0]
    elif n == 2:
        d = M[0][0] * M[1][1] - M[0][1] * M[1][0]
    else:
        d = sum(((-1) ** j) * M[0][j] * determinant(minor(M, 0, j))
                for j in range(n))
    return d % m if m else d

def adjugate(M):
    """Adjugate (transpose of the cofactor matrix) of a square matrix."""
    n = len(M)
    if n == 1:
        return [[1]]
    cof = [[((-1) ** (i + j)) * determinant(minor(M, i, j))
            for j in range(n)] for i in range(n)]
    return [[cof[j][i] for j in range(n)] for i in range(n)]

def is_invertible(M, m=MOD):
    """A matrix is invertible mod m iff gcd(det, m) = 1."""
    return gcd(determinant(M) % m, m) == 1

def mat_inverse(M, m=MOD):
    """Inverse of M modulo m:  K^-1 = det^-1 * adj(K)  (mod m)."""
    d = determinant(M) % m
    if gcd(d, m) != 1:
        raise ValueError(f"Matrix not invertible mod {m}: det = {d}, "
                         f"gcd(det,{m}) = {gcd(d, m)}")
    d_inv = mod_inverse(d, m)
    adj = adjugate(M)
    return [[(d_inv * x) % m for x in row] for row in adj]

# Text <-> number conversion
def clean_text(text):
    """Keep letters only and convert to upper case."""
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")

def text_to_nums(text):
    return [ord(c) - 65 for c in clean_text(text)]

def nums_to_text(nums):
    return "".join(chr((x % MOD) + 65) for x in nums)

def split_blocks(nums, n, pad=23):
    """Split into n-sized blocks; pad the last block with 'X' (23)."""
    nums = list(nums)
    while len(nums) % n:
        nums.append(pad)
    return [nums[i:i + n] for i in range(0, len(nums), n)]

# Key handling
def key_from_string(s, n):
    """Build an n x n key from an n*n-letter key word (row by row)."""
    nums = text_to_nums(s)
    if len(nums) != n * n:
        raise ValueError(f"Key word must have exactly {n * n} letters "
                         f"for a {n}x{n} key")
    K = [nums[i * n:(i + 1) * n] for i in range(n)]
    validate_key(K)
    return K

def key_to_string(K):
    return nums_to_text([x for row in K for x in row])

def validate_key(K):
    n = len(K)
    if any(len(r) != n for r in K):
        raise ValueError("Key must be a square matrix")
    if not is_invertible(K):
        d = determinant(K) % MOD
        raise ValueError(f"Invalid key: det = {d}, gcd(det, 26) = "
                         f"{gcd(d, MOD)} (must be 1)")
    return True

def count_invertible_keys(n):
    """|GL(n,Z26)| = |GL(n,Z2)| * |GL(n,Z13)|  (Chinese Remainder Th.)"""
    def gl(n, p):
        total = 1
        for i in range(n):
            total *= (p ** n - p ** i)
        return total
    return gl(n, 2) * gl(n, 13)

# Encryption / decryption
def encrypt(plaintext, K):
    n = len(K)
    validate_key(K)
    blocks = split_blocks(text_to_nums(plaintext), n)
    out = []
    for b in blocks:
        out.extend(mat_vec(K, b))
    return nums_to_text(out)

def decrypt(ciphertext, K):
    n = len(K)
    Kinv = mat_inverse(K)
    blocks = split_blocks(text_to_nums(ciphertext), n)
    out = []
    for b in blocks:
        out.extend(mat_vec(Kinv, b))
    return nums_to_text(out)

def random_invertible_key(n, rng):
    """Random valid key using the supplied random.Random instance."""
    while True:
        K = [[rng.randrange(MOD) for _ in range(n)] for _ in range(n)]
        if is_invertible(K):
            return K

def all_invertible_2x2():
    """Generator over every valid 2x2 key (brute-force demo)."""
    for a, b, c, d in product(range(MOD), repeat=4):
        if gcd((a * d - b * c) % MOD, MOD) == 1:
            yield [[a, b], [c, d]]
