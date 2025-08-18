from lwe import *
import numpy as np

def run_tests():
    print("q\tLWE_Fail(%)\tAnamorphic_Fail(%)\tLWE_from_apk_Fail(%)\tAnaEnc_RegDec_Fail(%)")

    for exp in range(5, 41):  # q = 2^5 to 2^20
        q = 2**exp
        lwe_failures = 0
        anamorphic_failures = 0
        lwe_from_apk_failures = 0
        anaenc_regdec_failures = 0

        runs = 100
        for _ in range(runs):
            # LWE Test
            try:
                sk, pk = key_gen(q)
                q, p, n, m, l, alpha = pk[0]
                mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
                ct = enc(pk, mu, p, q)
                dm = dec(sk, ct, p, q)
                if not np.array_equal(mu, dm):
                    lwe_failures += 1
            except Exception:
                lwe_failures += 1

            # Anamorphic LWE Test
            try:
                ask, apk, dk, tk = akey_gen(q)
                q, p, n, m, l, alpha = apk[0]
                mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
                s_mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
                c0, c1 = aenc(apk, dk, mu, s_mu)
                adm, _ = adec(dk, tk, ask, (c0, c1), apk[0])
                if not np.array_equal(adm, s_mu):
                    anamorphic_failures += 1
            except Exception:
                anamorphic_failures += 1

            # Regular LWE with (ask, apk)
            try:
                q, p, n, m, l, alpha = apk[0]
                mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
                ct = enc(apk, mu, p, q)
                dm = dec(ask, ct, p, q)
                if not np.array_equal(mu, dm):
                    lwe_from_apk_failures += 1
            except Exception:
                lwe_from_apk_failures += 1

            # Regular decryption on anamorphic ciphertext
            try:
                mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
                s_mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
                c0, c1 = aenc(apk, dk, mu, s_mu)
                dm = dec(ask, (c0, c1), p, q)
                if not np.array_equal(mu, dm):
                    anaenc_regdec_failures += 1
            except Exception:
                anaenc_regdec_failures += 1

        # Calculate percentages
        lwe_pct = round((lwe_failures / runs) * 100)
        anamorphic_pct = round((anamorphic_failures / runs) * 100)
        lwe_from_apk_pct = round((lwe_from_apk_failures / runs) * 100)
        anaenc_regdec_pct = round((anaenc_regdec_failures / runs) * 100)

        print(f"{('2^' + str(exp)):<6} "
              f"{(str(lwe_pct) + '%'):<14}"
              f"{(str(anamorphic_pct) + '%'):<22}"
              f"{(str(lwe_from_apk_pct) + '%'):<26}"
              f"{(str(anaenc_regdec_pct) + '%'):<26}")


if __name__ == "__main__":
    run_tests()
