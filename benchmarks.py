import time
import numpy as np
from lwe import *  # assumes: key_gen, akey_gen, enc, dec, aenc, adec

REPEATS = 100
q = 2**16

# Timing storage
times = {
    "key_gen": [],
    "a_key_gen": [],
    "regular_enc": [],
    "regular_dec": [],
    "a_enc": [],
    "a_dec": []
}

for _ in range(REPEATS):
    # Key Generation
    t0 = time.time()
    sk, pk = key_gen(q)
    t1 = time.time()
    times["key_gen"].append((t1 - t0) * 1000)

    t0 = time.time()
    ask, apk, dk, tk = akey_gen(q)
    t1 = time.time()
    times["a_key_gen"].append((t1 - t0) * 1000)

    # Common encryption input
    par = pk[0]
    q, p, n, m, l, alpha = par
    mu = np.random.randint(0, p, size=(l, 1))
    s_mu = np.random.randint(0, p, size=(l, 1))

    # Regular encryption
    t0 = time.time()
    ct = enc(pk, mu, p, q)
    t1 = time.time()
    times["regular_enc"].append((t1 - t0) * 1000)

    # Regular decryption
    t0 = time.time()
    dec_mu = dec(sk, ct, p, q)
    t1 = time.time()
    times["regular_dec"].append((t1 - t0) * 1000)

    # Anamorphic encryption
    t0 = time.time()
    act = aenc(apk, dk, mu, s_mu)
    t1 = time.time()
    times["a_enc"].append((t1 - t0) * 1000)

    # Anamorphic decryption
    t0 = time.time()
    s_mu_rec, _ = adec(dk, tk, ask, act, par)
    t1 = time.time()
    times["a_dec"].append((t1 - t0) * 1000)

# Summary
def avg(ms): return round(np.mean(ms), 3)

print("\nBenchmark Summary (times in milliseconds):")
print("============================================")
print("{:<35} {:>10}".format("Operation", "Avg Time (ms)"))
print("============================================")
print("{:<35} {:>10}".format("Key Generation", avg(times["key_gen"])))
print("{:<35} {:>10}".format("Anamorphic Key Generation", avg(times["a_key_gen"])))
print("{:<35} {:>10}".format("Regular Encryption", avg(times["regular_enc"])))
print("{:<35} {:>10}".format("Regular Decryption", avg(times["regular_dec"])))
print("{:<35} {:>10}".format("Anamorphic Encryption", avg(times["a_enc"])))
print("{:<35} {:>10}".format("Anamorphic Decryption", avg(times["a_dec"])))
print("============================================")
