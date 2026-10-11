#!/usr/bin/env python3
"""Exactness checks for cake formulas: slice identity, weight table, key window."""
import random

SLICE = 3_000_000
CAP = SLICE >> 1
H = 1464
TAG = 0x1f


def slice_cake(R, A, n):
    """cake_slice_from_service, transcribed."""
    cb = A >> 1
    work = min(R, cb >> 1)
    q = work // n
    base = q * n
    want = (q << 1) + (1 if (R - base >= n and cb - (base << 1) >= n) else 0)
    return max(min(want, CAP), H) & ~TAG


def slice_ref(R, A, n):
    return max(min(2 * (R // n), A // (2 * n), CAP), H) & ~TAG


def main():
    random.seed(1)
    cases = bad = 0
    for _ in range(400_000):
        n = random.choice([1, 2, 3, 7, random.randint(1, 1 << 20), random.randint(1, 1 << 40)])
        R = random.randint(0, 1 << random.randint(0, 50))
        A = random.randint(SLICE, SLICE + (1 << random.randint(0, 50)))
        cases += 1
        bad += slice_cake(R, A, n) != slice_ref(R, A, n)
    for n in range(1, 40):
        for R in range(400):
            for A in range(SLICE, SLICE + 400, 7):
                cb = A >> 1
                q = min(R, cb >> 1) // n
                base = q * n
                raw = (q << 1) + (R - base >= n and cb - (base << 1) >= n)
                cases += 1
                bad += raw != min(2 * (R // n), A // (2 * n))
    print(f"slice identity: {cases} cases, {bad} mismatches")

    w = [88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
         9548, 7620, 6100, 4904, 3906, 3121, 2501, 1991, 1586, 1277,
         1024, 820, 655, 526, 423, 335, 272, 215, 172, 137,
         110, 87, 70, 56, 45, 36, 29, 23, 18, 15]
    tab = [12097, 14964, 19009, 23204, 29587, 36830, 46174, 57404, 71827, 90109,
           112457, 140911, 176023, 218952, 274895, 344037, 429324, 539297, 677012, 840831,
           1048576, 1309441, 1639300, 2041334, 2538396, 3205199, 3947580, 4994148, 6242685, 7837531,
           9761289, 12341860, 15339168, 19173961, 23860929, 29826161, 37025580, 46684427, 59652323, 71582788]
    exact = all(tab[i] == (1024 << 20) // w[i] for i in range(40)) and (1024 << 20) // 3 == 357913941
    under = max(u * 1024 / w[i] - ((u * tab[i]) >> 20)
                for i in range(40) for u in (1_500_000, 3_000_000, 23_000_000))
    print(f"recip_weight == floor((1024 << 20) / weight): {exact}; "
          f"largest under-charge for a run <= 23 ms: {under:.2f} ns")

    cap_max = (CAP * ((1024 << 20) // 15)) >> 20
    window = cap_max + 2 * SLICE + ((SLICE >> 1) + (SLICE >> 2)) + (1 << 16)
    print(f"vtime cap max {cap_max / 1e6:.3f} ms; key window {window / 1e6:.3f} ms; "
          f"crossing at dt/16: {16 * window / 1e9:.3f} s, at dt/32: {32 * window / 1e9:.3f} s; "
          f"budget 2.500 s")


if __name__ == "__main__":
    main()
