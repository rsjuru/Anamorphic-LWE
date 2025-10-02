import math
import numpy as np
import random

# Security Parameter
lam = 16

# ----------------- Helper Sampling Functions -----------------

def sample_uniform_matrix(rows, cols, q):
    """
    Sample a matrix with uniform random integers in [0, q-1].
    Used for public matrix generation in GSW.
    """
    return np.random.randint(0, q-1, size=(rows, cols), dtype=int)


def sample_error_matrix(rows, cols, stddev, q):
    """
    Sample a small "error" matrix from a discrete Gaussian (rounded normal distribution).
    Used to introduce noise in GSW ciphertexts.
    """
    return np.round(np.random.normal(loc=0, scale=stddev, size=(rows, cols))).astype(int)


def sample_matrix_p(m, n):
    """
    Sample an m x n matrix from P ? {-1, 0, 1} with probabilites:
    -1 with 1/4, 0 with 1/2, +1 with 1/4
    Used for secret key generation.
    """
    # Sample integers from {0,1,2,3}
    r = np.random.randint(0, 4, size=(m, n))

    # Map values: {0,1 -> 0; 2 -> -1; 3 -> 1}
    matrix = np.where(r < 2, 0, np.where( r == 2, -1, 1))
    return matrix


# ----------------- Gadget Functions -----------------

def gadget_matrix(n, k, q):
    g = 2 ** np.arange(k)
    G = np.kron(np.eye(n, dtype=int), g) % q
    return G


def calculateSMatrix(k, l, q):
    # Extract bits from LSB to MSB
    q_bin = bin(q)[2:]  # remove the '0b' prefix

    q_bits = [int(b) for b in q_bin]


    # Build Sk
    Sk = np.zeros((k,k), dtype=int)
    for i in range(k):
        Sk[i,i] = 2
        if i > 0:
            Sk[i,i-1] = -1
        Sk[i,-1] = q_bits[i]   # last column

    # Build full S
    I = np.eye(l, dtype=int)
    S = np.kron(I, Sk)
    return S


# ----------------- Parameter Generation -----------------

def gen_parameters():

    # Sample modulus p, q poly(lambda)
    p = 128
    q = 2**18

    # Sample dimensions m, n = poly(lambda)
    m = lam**2 + random.randint(0, 10)
    n = lam + random.randint(0, 10)

    # Compute k
    k_upper = m**2 - math.ceil(p*lam*m/2)
    k_bound = m - (n*math.log2(q) + 2*lam)
    k_max = min(k_upper, k_bound)
    k = random.randint(1, max(1, int(k_max)))

    # Sample error rate alpha in (0,1)
    alpha = 1/(2*q)
    # Standard deviation sigma > alpha*q
    sigma = 1.5
    return q, p, m, n, alpha, sigma


# ----------------- Key Generation -----------------

def kgen():
    """
    Key generation for Dual-GSW.
    Outputs secret key sk and public key pk.
    """
    par = gen_parameters()
    q, p, m, n, alpha, sigma = par

    A = sample_uniform_matrix(n, m, q)
    s = sample_matrix_p(m, 1)

    # Compute s^T * A^T mod q
    As = np.matmul(s.T, A.T) % q

    # Public key: vertically stack A^T and As
    B = np.vstack([A.T, As])

    pk = (par, B)
    sk = s
    return sk, pk


# ----------------- Anamorphic Key Generation -----------------

def agen():
    # Generate parameters
    par = gen_parameters()
    q, p, m, n, alpha, sigma = par

    # Compute k (your heuristic; keep as-is)
    k = math.ceil((m/2) - math.ceil(math.sqrt((lam*m)/2)))
    limit = n*math.log2(q)+2*lam
    if m-k <= limit:
        k = math.ceil(k/2)

    print("m=", m, " k=", k)

    # Sample s <- P^m and define J = { j : s_j = 0}
    s = sample_matrix_p(m, 1)
    J =[i for i in range(m) if s[i, 0] == 0]

    # If |J| < k, abort (retry a few times)
    max_tries = 10
    tries = 0
    while len(J) < k and tries < max_tries:
        s = sample_matrix_p(m, 1)
        J = [i for i in range(m) if s[i, 0] == 0]
        tries += 1
    if len(J) < k:
        return None, None, None, None

    # Choose I subset uniformly of size k from J
    I = sorted(random.sample(J, k))

    # Sample A_bar and T
    A_bar = sample_uniform_matrix(m - k, n, q)   # shape (m-k, n)
    T = sample_matrix_p(m-k, k)                  # shape (m-k, k)

    # Compute last k rows: T^T * A_bar => shape (k, n)
    TT_Abar = (T.T @ A_bar) % q

    # Build A' of shape (m x n): stack A_bar then TT_Abar
    A_prime = np.vstack([A_bar, TT_Abar]) % q  # (m, n)

    # Permute A' rows to form A according to I and complement
    full_indices = list(range(m))
    complement = [idx for idx in full_indices if idx not in I]
    if len(complement) != (m - k):
        raise AssertionError("complement size mismatch")

    A = np.zeros((m, n), dtype=np.int64)

    # CORRECTED: place A_prime[j,:] in complement[j]
    for j in range(m - k):
        idx = complement[j]
        A[idx, :] = A_prime[j, :] % q

    for j in range(k):
        idx = I[j]
        A[idx, :] = A_prime[m - k + j, :] % q

    # Compute As = s^T * A  (1 x n)
    As = (s.T @ A) % q

    # Public key B = [ A ; As ]  -> shape (m+1, n)
    B = np.vstack([A, As]) % q

    # Build T' := [ -T^T | I_k ]  (k x m)
    neg_TT = (-T.T) % q
    I_k = np.eye(k, dtype=np.int64) % q
    Tprime = np.hstack([neg_TT, I_k]) % q  # shape (k, m)

    # Reorder columns of Tprime to form eT
    eT = np.zeros((k, m), dtype=np.int64)
    for j in range(m - k):
        col_dst = complement[j]
        eT[:, col_dst] = Tprime[:, j] % q
    for j in range(k):
        col_dst = I[j]
        eT[:, col_dst] = Tprime[:, (m - k) + j] % q

    # Sanity checks
    lhs = (Tprime @ A_prime) % q
    if not np.all(lhs == 0):
        print("Warning: Tprime @ A_prime.T != 0 (mod q)")

    te_at = (eT @ A) % q
    if not np.all(te_at == 0):
        print("Warning: eT @ A.T != 0 (mod q)")

    apk = (par, B)
    ask = s
    dk = (k, I)
    tk = eT

    return ask, apk, dk, tk


# ----------------- Encryption -----------------

def enc(pk, mu):
    """
    Encrypt a plaintext mu using Dual Regev.
    pk: public key
    mu: plaintext integer in [0, p-1]
    """
    par = pk[0]
    B = pk[1]
    q, p, m, n, alpha, sigma = par
    delta = math.ceil(q/p)

    # Sample uniformly vector r
    r = sample_uniform_matrix(n, 1, q)

    # Sample error vectors e0 and e1
    e0 = sample_error_matrix(m, 1, sigma, q)
    e1 = sample_error_matrix(1, 1, sigma, q)

    # Compute B*r
    Br = np.matmul(B, r)

    # Vertically stack e0 and e1
    e = np.vstack([e0, e1])

    # Vertically stack O^m and mu
    zeros = np.zeros((m,1), dtype=int)
    mu_stack = np.vstack([zeros, np.array([mu])])
    delta_mustack = delta*mu_stack

    # Compute c = Br + e + delta*mustack
    c = (Br + e + delta_mustack) % q
    return c


# ----------------- Anamorphic Encryption -----------------

def aenc(apk, dk, mu, mu_hat):
    par, B = apk
    q, p, m, n, alpha, sigma = par

    k, I = dk

    # Delta = ceil(q/p)
    delta = int(math.ceil(q / p))

    # Sample uniform vector r
    r = sample_uniform_matrix(n, 1, q)

    # Sample error vector e0 and e1
    e0 = sample_error_matrix(m, 1, sigma, q)
    e1 = sample_error_matrix(1, 1, sigma, q)

    # Compute f_mu_hat (mx1) with mu_hat entries placed at indices I
    f = np.zeros((m,1), dtype=np.int64)
    for j, idx in enumerate(I):
        # idx is 0-based index in [0...m-1]
        f[idx, 0] = int(mu_hat[j])

    # Compute Br = B * r mod q
    Br = np.matmul(B, r) % q

    # Stack e = [e0; e1]
    e = np.vstack([e0, e1])

    # Stack delta*[f; mu]
    mu_col = np.array([[int(mu)]], dtype=np.int64)
    f_and_mu = np.vstack([f, mu_col])
    delta_term = (delta * f_and_mu) % q

    # Compute c = Br + e + delta*f_and_mu
    c = (Br + e + delta_term) % q
    return c


# ----------------- Decryption -----------------

def dec(par, sk, ct):
    """
    Decrypt a ciphertext ct using Dual Regev.
    Returns plaintext integer mu.
    """
    q, p, m, n, alpha, sigma = par
    delta_float = q/p
    delta = math.ceil(q/p)
    print(delta_float)
    print(delta)

    # Construct sk_neg = [-sk^T | 1]
    sk_neg = np.concatenate([-sk.T, np.array([[1]])], axis=1)

    # Compute nu = [-sk^T | 1] * ct
    nu = np.matmul(sk_neg, ct) % q
    mu = int(np.round(nu.item() / delta)) % p
    return mu


# ----------------- Anamorphic Decryption -----------------

def adec(par, dk, tk, ask, act):
    k, I = dk
    q, p, m, n, alpha, sigma = par
    delta = int(math.ceil(q/p))

    # Build [Te | 0] (k x (m+1))
    zero_col = np.zeros((k, 1), dtype=np.int64)
    Te_ext = np.hstack([tk, zero_col])

    nu_hat = np.matmul(Te_ext, act) % q

    mu_hat = np.round(nu_hat / delta).astype(np.int64) % p

    return mu_hat


# ----------------- Testing -----------------

# Number of trials
iterations = 1000
regular_success = 0
anamorphic_success = 0

sk, pk = kgen()
par = pk[0]
q, p, m, n, alpha, sigma = par

for i in range(iterations):
    mu = random.randint(0, p-1)
    ct = enc(pk, mu)
    dm = dec(par, sk, ct)

    if mu == dm:
        regular_success += 1
    else:
        print("Original message: ",mu, " and decrypted message: ", dm)

ask, apk, dk, tk = agen()
par = apk[0]
q, p, m, n, alpha, sigma = par

for i in range(iterations):
    mu = random.randint(0, p-1)
    mu_hat = sample_uniform_matrix(dk[0], 1, p)
    act = aenc(apk, dk, mu, mu_hat)

    adm = adec(par, dk, tk, ask, act)

    if np.array_equal(mu_hat, adm):
        anamorphic_success += 1
    else:
        print("Anamorphic message: ", mu_hat.T, " and decrypted message: ", adm.T)

print(f"{regular_success}/{iterations} regular decryptions succeeded!")
print(f"{anamorphic_success}/{iterations} anamorphic decryptions succeeded!")