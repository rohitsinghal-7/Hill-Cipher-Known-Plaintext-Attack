"""
experiments.py - reproducible experiments for the mini project report
Cyber Security Lab (7CS4-22) - CSL-G04 : Hill Cipher with Known-Plaintext Attack

Runs (seeded, so the numbers are repeatable):
  E1  probability that a random plaintext matrix is invertible mod 26
  E2  attack success rate versus number of known blocks (direct vs full attack)
  E3  running time of the attack versus key size n
  E4  known-plaintext attack versus brute force (2x2)
  E5  ambiguity when too few pairs are known (2x2)
Writes results/results.json and (if matplotlib is installed) two graphs.
"""
import json
import os
import random
import statistics
import time

from hill_cipher import (random_invertible_key, encrypt, is_invertible, transpose,
                         count_invertible_keys, key_to_string, MOD)
from known_plaintext_attack import (recover_key, attack_direct, make_pairs,
                                    brute_force_2x2, count_consistent_keys_2x2,
                                    AttackError)

SEED = 2026
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")


def rand_text(rng, length):
    return "".join(chr(65 + rng.randrange(26)) for _ in range(length))


def e1_invertible_probability(rng, trials=20000):
    print("\nE1  P(random plaintext matrix is invertible mod 26)")
    print(f"{'n':>2} {'exact':>10} {'empirical':>10}")
    rows = {}
    for n in (2, 3, 4):
        exact = count_invertible_keys(n) / MOD ** (n * n)
        hit = 0
        for _ in range(trials):
            M = [[rng.randrange(MOD) for _ in range(n)] for _ in range(n)]
            hit += is_invertible(M)
        emp = hit / trials
        rows[n] = {"exact": exact, "empirical": emp}
        print(f"{n:>2} {exact:>10.4f} {emp:>10.4f}")
    return rows


def e2_success_vs_pairs(rng, trials=2000):
    print("\nE2  Attack success rate (%) vs number of known blocks k")
    print(f"{'n':>2} {'k':>3} {'direct(first n)':>16} {'full attack':>12}")
    rows = {}
    for n in (2, 3):
        for k in range(n, n + 6):
            d_ok = f_ok = 0
            for _ in range(trials):
                K = random_invertible_key(n, rng)
                pt = rand_text(rng, n * k)
                ct = encrypt(pt, K)
                pairs = make_pairs(pt, ct, n)
                try:
                    d_ok += attack_direct(pairs, n) == K
                except AttackError:
                    pass
                try:
                    f_ok += recover_key(pt, ct, n)["key"] == K
                except AttackError:
                    pass
            rows[f"{n}-{k}"] = {"n": n, "k": k, "direct": 100 * d_ok / trials,
                                "full": 100 * f_ok / trials}
            print(f"{n:>2} {k:>3} {100 * d_ok / trials:>15.1f}% {100 * f_ok / trials:>11.1f}%")
    return rows


def e3_timing(rng, reps=200):
    print("\nE3  Attack running time vs key size (k = n + 3 blocks, mean of %d runs)" % reps)
    print(f"{'n':>2} {'key space':>22} {'mean time (us)':>15}")
    rows = {}
    for n in (2, 3, 4, 5):
        times = []
        for _ in range(reps):
            K = random_invertible_key(n, rng)
            pt = rand_text(rng, n * (n + 3))
            ct = encrypt(pt, K)
            t0 = time.perf_counter()
            try:
                recover_key(pt, ct, n)
            except AttackError:
                continue
            times.append(time.perf_counter() - t0)
        mean_us = statistics.mean(times) * 1e6
        rows[n] = {"keyspace": count_invertible_keys(n), "mean_us": mean_us}
        print(f"{n:>2} {count_invertible_keys(n):>22,} {mean_us:>15.1f}")
    return rows


def e4_vs_bruteforce(rng, runs=10):
    print("\nE4  KPA versus brute force on 2x2 keys (%d random keys)" % runs)
    tried_list, bf_times, kpa_times = [], [], []
    for _ in range(runs):
        K = random_invertible_key(2, rng)
        while True:                       # use a known text that fixes the key uniquely
            pt = rand_text(rng, 12)
            ct = encrypt(pt, K)
            try:
                r = recover_key(pt, ct, 2)
                break
            except AttackError:
                continue
        found, tried, secs = brute_force_2x2(pt, ct)
        assert r["key"] == K and found == K
        tried_list.append(tried)
        bf_times.append(secs)
        kpa_times.append(r["seconds"])
    rate = statistics.mean(tried_list) / statistics.mean(bf_times)
    res = {"avg_keys_tried": statistics.mean(tried_list),
           "avg_bf_seconds": statistics.mean(bf_times),
           "avg_kpa_seconds": statistics.mean(kpa_times),
           "bf_keys_per_second": rate,
           "est_3x3_bruteforce_days": count_invertible_keys(3) / 2 / rate / 86400}
    print(f"  average keys tried by brute force : {res['avg_keys_tried']:.0f} "
          f"of {count_invertible_keys(2)}")
    print(f"  average brute-force time          : {res['avg_bf_seconds'] * 1000:.1f} ms")
    print(f"  average KPA time                  : {res['avg_kpa_seconds'] * 1e6:.1f} us")
    print(f"  brute-force speed                 : {rate:,.0f} keys/s")
    print(f"  est. brute force for 3x3 (avg)    : {res['est_3x3_bruteforce_days']:.1f} days")
    return res


def e5_ambiguity():
    print("\nE5  Keys consistent with the known pairs (2x2, key = DDCF)")
    K = [[3, 3], [2, 5]]
    rows = {}
    for text in ("HE", "HELP", "HEHE", "HELPME"):
        pairs = make_pairs(text, encrypt(text, K), 2)
        c = count_consistent_keys_2x2(pairs)
        rows[text] = c
        print(f"  known plaintext {text:<7} ({len(pairs)} block(s)) -> {c} candidate key(s)")
    return rows


def make_graphs(e2, e3):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed - graphs skipped")
        return
    os.makedirs(OUT, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6.2, 3.8), dpi=200)
    for n, style in ((2, "o"), (3, "s")):
        ks = [v["k"] for v in e2.values() if v["n"] == n]
        ax.plot(ks, [v["direct"] for v in e2.values() if v["n"] == n], style + "--",
                label=f"{n}x{n}: direct (first {n} blocks)")
        ax.plot(ks, [v["full"] for v in e2.values() if v["n"] == n], style + "-",
                label=f"{n}x{n}: full attack")
    ax.set_xlabel("Number of known plaintext blocks (k)")
    ax.set_ylabel("Key recovered (%)")
    ax.set_ylim(0, 105)
    ax.grid(alpha=0.3)
    ax.legend(fontsize=7, loc="lower right")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "success_vs_blocks.png"))
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(6.2, 3.6), dpi=200)
    ns = sorted(e3)
    ax.bar([str(n) + "x" + str(n) for n in ns], [e3[n]["mean_us"] for n in ns],
           color="#2f4b7c")
    ax.set_ylabel("Mean attack time (microseconds)")
    ax.set_xlabel("Key size")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "time_vs_keysize.png"))
    plt.close(fig)


def main():
    rng = random.Random(SEED)
    results = {
        "e1": e1_invertible_probability(rng),
        "e2": e2_success_vs_pairs(rng),
        "e3": e3_timing(rng),
        "e4": e4_vs_bruteforce(rng),
        "e5": e5_ambiguity(),
    }
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "results.json"), "w") as f:
        json.dump(results, f, indent=2)
    make_graphs(results["e2"], results["e3"])
    print("\nResults saved to results/results.json")


if __name__ == "__main__":
    main()
