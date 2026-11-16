"""
main.py - menu driven front end
Cyber Security Lab (7CS4-22) - Mini Project CSL-G04
Hill Cipher with Known-Plaintext Attack

Usage:
    python main.py            interactive menu
    python main.py --demo     run the scripted demonstration (no input needed)

For lab/learning use on test data only.
"""
import random
import sys

from hill_cipher import (key_from_string, key_to_string, encrypt, decrypt,
                         mat_inverse, determinant, random_invertible_key,
                         count_invertible_keys, MOD)
from known_plaintext_attack import (recover_key, chosen_plaintext_attack,
                                    brute_force_2x2, make_pairs,
                                    count_consistent_keys_2x2, AttackError)


def show_matrix(name, M):
    print(f"{name} =")
    for row in M:
        print("   [ " + " ".join(f"{x:2d}" for x in row) + " ]")


def ask_key():
    n = int(input("Key size n (2 or 3): ").strip())
    word = input(f"Key word ({n * n} letters, row by row): ").strip()
    return key_from_string(word, n)


def do_encrypt():
    K = ask_key()
    pt = input("Plaintext: ")
    show_matrix("Key K", K)
    print("Ciphertext :", encrypt(pt, K))


def do_decrypt():
    K = ask_key()
    ct = input("Ciphertext: ")
    show_matrix("Inverse key K^-1", mat_inverse(K))
    print("Plaintext  :", decrypt(ct, K))


def do_kpa():
    n = int(input("Key size n used by the sender (2 or 3): ").strip())
    pt = input("Known plaintext : ")
    ct = input("Matching cipher : ")
    try:
        r = recover_key(pt, ct, n)
    except AttackError as e:
        print("[-] Attack failed:", e)
        return
    show_matrix("Recovered key K", r["key"])
    print("Key word       :", key_to_string(r["key"]))
    print("Method used    :", r["method"])
    print(f"Blocks used    : {r['blocks']}   Time: {r['seconds'] * 1e6:.1f} microseconds")


def do_cpa():
    K = ask_key()
    n = len(K)
    rec = chosen_plaintext_attack(lambda m: encrypt(m, K), n)
    show_matrix("Key recovered by chosen-plaintext attack", rec)
    print("Matches secret key:", rec == K)


def do_bruteforce():
    word = input("Secret 2x2 key word (4 letters, to build a test case): ").strip()
    K = key_from_string(word, 2)
    pt = input("Known plaintext (>= 4 letters): ")
    ct = encrypt(pt, K)
    found, tried, secs = brute_force_2x2(pt, ct)
    print(f"Key found: {key_to_string(found)} after {tried} of {count_invertible_keys(2)} "
          f"keys in {secs:.3f} s")


def demo():
    print("=" * 66)
    print(" Hill Cipher with Known-Plaintext Attack - scripted demonstration")
    print("=" * 66)
    K2 = key_from_string("DDCF", 2)
    show_matrix("2x2 key K", K2)
    ct = encrypt("HELP", K2)
    print("Encrypt HELP ->", ct, "| decrypt ->", decrypt(ct, K2))
    r = recover_key("HELP", ct, 2)
    print("KPA recovers   :", key_to_string(r["key"]), "via", r["method"])
    print()
    K3 = key_from_string("GYBNQKURP", 3)
    show_matrix("3x3 key K", K3)
    pt = "ENCRYPTIONALGORITHM"
    ct = encrypt(pt, K3)
    print("Plaintext      :", pt)
    print("Ciphertext     :", ct)
    r = recover_key(pt[:9], ct[:9], 3)
    print("KPA (9 letters):", key_to_string(r["key"]), "via", r["method"])
    print("Key correct    :", r["key"] == K3)


MENU = """
================ HILL CIPHER LAB (CSL-G04) ================
 1. Encrypt a message
 2. Decrypt a message
 3. Known-plaintext attack (recover the key)
 4. Chosen-plaintext attack demo
 5. Brute-force 2x2 key search (comparison)
 6. Scripted demonstration
 0. Exit
==========================================================="""


def main():
    if "--demo" in sys.argv:
        demo()
        return
    actions = {"1": do_encrypt, "2": do_decrypt, "3": do_kpa,
               "4": do_cpa, "5": do_bruteforce, "6": demo}
    while True:
        print(MENU)
        choice = input("Choice: ").strip()
        if choice == "0":
            print("Goodbye.")
            break
        fn = actions.get(choice)
        if not fn:
            print("Invalid choice.")
            continue
        try:
            fn()
        except (ValueError, AttackError) as e:
            print("[!] Error:", e)


if __name__ == "__main__":
    main()
