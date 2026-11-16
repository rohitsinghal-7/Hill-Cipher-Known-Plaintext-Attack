"""
Unit tests for the Hill cipher and the known-plaintext attack.
Run from the project root:   python -m unittest discover -s tests -v
"""
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from hill_cipher import (mod_inverse, determinant, is_invertible, mat_inverse, transpose,
                         mat_mul, identity, key_from_string, key_to_string,
                         encrypt, decrypt, random_invertible_key,
                         count_invertible_keys, clean_text)
from known_plaintext_attack import (make_pairs, recover_key, attack_direct, attack_subset,
                                    attack_crt, solve_mod_prime, verify_key,
                                    chosen_plaintext_attack, brute_force_2x2,
                                    count_consistent_keys_2x2, AttackError)


class TestMath(unittest.TestCase):
    def test_mod_inverse_values(self):
        self.assertEqual(mod_inverse(3), 9)
        self.assertEqual(mod_inverse(25), 25)
        self.assertEqual(mod_inverse(15), 7)

    def test_mod_inverse_all_units(self):
        for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25):
            self.assertEqual((a * mod_inverse(a)) % 26, 1)

    def test_mod_inverse_non_unit_raises(self):
        for a in (0, 2, 13, 26):
            with self.assertRaises(ValueError):
                mod_inverse(a)

    def test_determinant_2x2_3x3(self):
        self.assertEqual(determinant([[3, 3], [2, 5]]), 9)
        self.assertEqual(determinant([[2, 0, 1], [1, 3, 2], [1, 1, 1]]), -0 + 2*(3-2) - 0 + 1*(1-3))

    def test_matrix_inverse_2x2(self):
        K = [[3, 3], [2, 5]]
        self.assertEqual(mat_inverse(K), [[15, 17], [20, 9]])
        self.assertEqual(mat_mul(K, mat_inverse(K)), identity(2))

    def test_matrix_inverse_3x3(self):
        K = key_from_string("GYBNQKURP", 3)
        self.assertEqual(mat_mul(K, mat_inverse(K)), identity(3))

    def test_singular_matrix_rejected(self):
        self.assertFalse(is_invertible([[2, 4], [1, 2]]))      # det 0
        self.assertFalse(is_invertible([[2, 3], [4, 5]]))      # det -2 -> gcd 2
        self.assertFalse(is_invertible([[13, 0], [0, 1]]))     # det 13
        with self.assertRaises(ValueError):
            mat_inverse([[2, 4], [1, 2]])


class TestCipher(unittest.TestCase):
    def test_known_vector_2x2(self):
        self.assertEqual(encrypt("HELP", [[3, 3], [2, 5]]), "HIAT")

    def test_known_vector_3x3(self):
        K = key_from_string("GYBNQKURP", 3)
        self.assertEqual(encrypt("ACT", K), "POH")
        self.assertEqual(decrypt("POH", K), "ACT")

    def test_roundtrip_2x2(self):
        K = key_from_string("HILL", 2)
        msg = "MEETMEATTHELIBRARYATNOON"
        self.assertEqual(decrypt(encrypt(msg, K), K), msg)

    def test_roundtrip_3x3_with_padding(self):
        K = key_from_string("GYBNQKURP", 3)
        ct = encrypt("HELLO", K)                 # padded with X to 6 letters
        self.assertEqual(len(ct), 6)
        self.assertEqual(decrypt(ct, K), "HELLOX")

    def test_input_is_cleaned(self):
        K = [[3, 3], [2, 5]]
        self.assertEqual(encrypt("he, lp!", K), encrypt("HELP", K))
        self.assertEqual(clean_text("a1b-C"), "ABC")

    def test_invalid_key_rejected(self):
        with self.assertRaises(ValueError):
            key_from_string("ABCD", 2)           # det = 0
        with self.assertRaises(ValueError):
            key_from_string("ABC", 2)            # wrong length

    def test_key_string_roundtrip(self):
        self.assertEqual(key_to_string(key_from_string("GYBNQKURP", 3)), "GYBNQKURP")

    def test_random_keys_roundtrip(self):
        rng = random.Random(1)
        for n in (2, 3, 4):
            for _ in range(20):
                K = random_invertible_key(n, rng)
                msg = "".join(chr(65 + rng.randrange(26)) for _ in range(n * 7))
                self.assertEqual(decrypt(encrypt(msg, K), K), msg)

    def test_key_space_sizes(self):
        self.assertEqual(count_invertible_keys(2), 157248)
        self.assertEqual(count_invertible_keys(3), 1634038189056)


class TestAttack(unittest.TestCase):
    def test_direct_attack_2x2(self):
        K = [[3, 3], [2, 5]]
        r = recover_key("HELP", encrypt("HELP", K), 2)
        self.assertEqual(r["key"], K)
        self.assertIn("Direct", r["method"])

    def test_direct_attack_3x3(self):
        K = key_from_string("GYBNQKURP", 3)
        r = recover_key("ENCRYPTION", encrypt("ENCRYPTION", K), 3)   # 3 full blocks
        self.assertEqual(r["key"], K)
        self.assertIn("Direct", r["method"])

    def test_3x3_even_determinant_needs_fallback(self):
        # CYB|ERS|ECU gives det(P) = 18 (even): direct inversion is impossible,
        # but a 4th block (RIT) makes the system solvable mod 2 and mod 13
        K = key_from_string("GYBNQKURP", 3)
        pt = "CYBERSECURITY"
        r = recover_key(pt, encrypt(pt, K), 3)
        self.assertEqual(r["key"], K)
        self.assertNotIn("Direct", r["method"])
        with self.assertRaises(AttackError):                  # det(P)=20, 3 blocks only
            recover_key("CRYPTOGRAM", encrypt("CRYPTOGRAM", K), 3)

    def test_attack_with_long_text(self):
        K = key_from_string("GYBNQKURP", 3)
        pt = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        self.assertEqual(recover_key(pt, encrypt(pt, K), 3)["key"], K)

    def test_singular_plaintext_falls_back(self):
        # first two blocks AA/AB-type -> P singular, later blocks fix it
        K = [[3, 3], [2, 5]]
        pt = "AAAAHELP"
        r = recover_key(pt, encrypt(pt, K), 2)
        self.assertEqual(r["key"], K)
        self.assertNotIn("Direct", r["method"])

    def test_crt_when_no_subset_is_invertible(self):
        # LE|NN|SU: every pair of blocks has a determinant that is not a unit
        # mod 26, so the subset search fails, yet the blocks together have full
        # rank mod 2 and mod 13, so the mod-2 / mod-13 + CRT solver succeeds.
        K = [[3, 3], [2, 5]]
        pt = "LENNSU"
        pairs = make_pairs(pt, encrypt(pt, K), 2)
        for i, j in ((0, 1), (0, 2), (1, 2)):
            self.assertFalse(is_invertible(transpose([pairs[i][0], pairs[j][0]])))
        with self.assertRaises(AttackError):
            attack_subset(pairs, 2)
        self.assertEqual(attack_crt(pairs, 2), K)
        r = recover_key(pt, encrypt(pt, K), 2)
        self.assertEqual(r["key"], K)
        self.assertIn("CRT", r["method"])

    def test_too_few_pairs_fails(self):
        K = [[3, 3], [2, 5]]
        with self.assertRaises(AttackError):
            recover_key("HE", encrypt("HE", K), 2)         # only one block

    def test_repeated_blocks_fail(self):
        K = [[3, 3], [2, 5]]
        pt = "HEHEHEHE"
        with self.assertRaises(AttackError):
            recover_key(pt, encrypt(pt, K), 2)

    def test_inconsistent_pairs_detected(self):
        K = [[3, 3], [2, 5]]
        ct = encrypt("HELPMEPLZ", K)
        bad = ct[:-2] + "ZZ"                                # corrupt last block
        pairs = make_pairs("HELPMEPLZX", bad + "", 2)
        with self.assertRaises(AttackError):
            attack_crt(pairs + [([1, 1], [0, 0])], 2)

    def test_chosen_plaintext(self):
        K = key_from_string("GYBNQKURP", 3)
        self.assertEqual(chosen_plaintext_attack(lambda m: encrypt(m, K), 3), K)

    def test_brute_force_agrees(self):
        K = [[3, 3], [2, 5]]
        found, tried, _ = brute_force_2x2("HELP", encrypt("HELP", K))
        self.assertTrue(verify_key(found, make_pairs("HELP", encrypt("HELP", K), 2)))
        self.assertGreater(tried, 0)

    def test_ambiguity_with_one_pair(self):
        K = [[3, 3], [2, 5]]
        pairs = make_pairs("HE", encrypt("HE", K), 2)
        self.assertGreater(count_consistent_keys_2x2(pairs), 1)
        pairs2 = make_pairs("HELP", encrypt("HELP", K), 2)
        self.assertEqual(count_consistent_keys_2x2(pairs2), 1)

    def test_random_attacks_n2_n3_n4(self):
        rng = random.Random(7)
        for n in (2, 3, 4):
            for _ in range(25):
                K = random_invertible_key(n, rng)
                pt = "".join(chr(65 + rng.randrange(26)) for _ in range(n * (n + 6)))
                self.assertEqual(recover_key(pt, encrypt(pt, K), n)["key"], K)


if __name__ == "__main__":
    unittest.main(verbosity=2)
