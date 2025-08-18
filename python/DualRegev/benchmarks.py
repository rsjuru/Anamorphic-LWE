import time
import numpy as np
from dualRegev import *

REPEATS = 1000
q = 2**16

# Timing storage
times = {
    "kgen": [],
    "agen": [],
    "enc": [],
    "dec": [],
    "aenc": [],
    "adec": []
}

for _ in range(REPEATS):
    # Key Generation
    t0 = time.time()
    sk, pk = kgen(q)
    t1 = time.time()
    times["kgen"].append((t1 - t0)*1000)

    t0 = time.time()
    ask, apk, dk, tk = agen(q)
    t1 = time.time()
    times["agen"].append((t1 - t0)*1000)

    # Common encryption input
    par = pk[0]
    q, p, n, m_bar, alpha, std_dev = par
    mu = sample_uniform_matrix(n, 1, p)
    mu_bar = sample_uniform_matrix(n, 1, p)

    # Regular encryption
    t0 = time.time()
    ct = enc(pk, mu)
    t1 = time.time()
    times["enc"].append((t1 - t0)*1000)

    # Regular decryption
    t0 = time.time()
    dm = dec(sk, ct, p, q)
    t1 = time.time()
    times["dec"].append((t1 - t0)*1000)

    # Anamorphic encryption
    t0 = time.time()
    act = aenc(apk, dk, mu, mu_bar)
    t1 = time.time()
    times["aenc"].append((t1 - t0)*1000)

    # Anamorphic decryption
    t0 = time.time()
    sm, _ = adec(apk, dk, tk, ask, act)
    t1 = time.time()
    times["adec"].append((t1 - t0)*1000)


def avg(ms): return round(np.mean(ms), 3)

print("\nBenchmark Summary (times in milliseconds):")
print("============================================")
print("{:<35} {:>10}".format("Operation", "Avg Time (ms)"))
print("============================================")
print("{:<35} {:>10}".format("Key Generation", avg(times["kgen"])))
print("{:<35} {:>10}".format("Anamorphic Key Generation", avg(times["agen"])))
print("{:<35} {:>10}".format("Regular Encryption", avg(times["enc"])))
print("{:<35} {:>10}".format("Regular Decryption", avg(times["dec"])))
print("{:<35} {:>10}".format("Anamorphic Encryption", avg(times["aenc"])))
print("{:<35} {:>10}".format("Anamorphic Decryption", avg(times["adec"])))
print("============================================")