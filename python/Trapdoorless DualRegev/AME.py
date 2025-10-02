import math
import numpy as np
import random

# Security Parameter
lam = 128

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
    print(nu.item() / delta)
    mu = int(np.round(nu.item() / delta)) % p
    return mu


# ----------------- Testing -----------------

iterations = 1000
regular_success = 0

sk, pk = kgen()
q, p, m, n, alpha, sigma = pk[0]

for i in range(iterations):
    print("Iteration round: ", i+1)
    mu = random.randint(0, p-1)
    ct = enc(pk, mu)
    dm = dec(pk[0], sk, ct)

    if mu == dm:
        regular_success += 1
    else:
        print("Original message: ", mu, " and decrypted message: ", dm)

print(f"{regular_success}/{iterations} regular decryptions succeeded!")

