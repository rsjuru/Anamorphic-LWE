from dualRegev import *
import numpy as np

RUNS = 100


def run_tests():
    print("q\tLWE_Fail(%)\tAnamorphic_Fail(%)\tLWE_from_apk_Fail(%)\tAnaEnc_RegDec_Fail(%)")

    for exp in range(5, 41):
        q = 2**exp
        dec_failures = 0
        anamorphic_failures = 0
        reg_dec_ana_failures = 0
        aenc_dec_failures = 0

        for _ in range(RUNS):
            # Regular dec test
            try:
                sk, pk = kgen(q)
                p, q, n, m_bar, alpha, std_dev = pk[0]
                mu = sample_uniform_matrix(n, 1, p)
                ct = enc(pk, mu)
                dm = dec(sk, ct, p, q)
                if not np.array_equal(mu, dm):
                    dec_failures += 1
            except Exception:
                dec_failures += 1

            # Anamorphic LWE Test
            try:
                ask, apk, dk, tk = agen(q)
                p, q, n, m_bar, alpha, std_dev = apk[0]
                mu = sample_uniform_matrix(n, 1, p)
                mu_bar = sample_uniform_matrix(n, 1, p)
                act = aenc(apk, dk, mu, mu_bar)
                adm, _ = adec(apk, dk, tk, ask, act)
                if not np.array_equal(mu_bar, adm):
                    anamorphic_failures += 1
            except Exception:
                anamorphic_failures += 1

            # Regular LWE with apk and ask
            try:
                p, q, n, m_bar, alpha, std_dev = apk[0]
                mu = sample_uniform_matrix(n, 1, p)
                ct = enc(apk, mu)
                dm = dec(ask, ct, p, q)
                if not np.array_equal(mu, dm):
                    reg_dec_ana_failures += 1
            except Exception:
                reg_dec_ana_failures += 1

            # Regular decryption on anamorphic ciphertext
            try:
                mu = sample_uniform_matrix(n, 1, p)
                mu_bar = sample_uniform_matrix(n, 1, p)
                act = aenc(apk, dk, mu, mu_bar)
                dm = dec(ask, act, p, q)
                if not np.array_equal(mu, dm):
                    aenc_dec_failures += 1
            except Exception:
                aenc_dec_failures += 1

        # Calculate percentages
        reg_pct = round((dec_failures / RUNS) * 100)
        anamorphic_pct = round((anamorphic_failures / RUNS) * 100)
        lwe_with_akeys_pct = round((reg_dec_ana_failures / RUNS) * 100)
        aenc_dec_pct = round((aenc_dec_failures / RUNS) * 100)

        print(f"{('2^' + str(exp)):<6} "
              f"{(str(reg_pct) + '%'):<14}"
              f"{(str(anamorphic_pct) + '%'):<22}"
              f"{(str(lwe_with_akeys_pct) + '%'):<26}"
              f"{(str(aenc_dec_pct) + '%'):<26}")


if __name__ == "__main__":
    run_tests()