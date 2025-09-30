import math
import numpy as np
import random

# Security Parameter
lam = 2
# Multiplicational depth
L = 3


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


def gadget_matrix(n, k, q):
    """
    Construct the gadget matrix G of size n*k, defined as:
    G = I_n ⊗ [1, 2, 4, ..., 2^{k-1}]
    Used in encryption for embedding plaintexts.
    """
    g = 2 ** np.arange(k) # [1, 2, 4, ..., 2^{k-1}
    G = np.kron(np.eye(n, dtype= int), g) % q
    return G


def gadget_inverse(vec, q, base=2):
    """
    Gadget decomposition: express each entry of vec in base "base".
    Returns a vector of digits (LSB first).
    """
    vec = np.asarray(vec, dtype=int).reshape(-1) # flatten vector
    k = int(np.ceil(np.log(q) / np.log(base))) # number of digits needed

    digits = []
    for x in vec:
        coeffs = []
        y = int(x) # convert to integer
        for _ in range(k):
            coeffs.append(y % base) # extract least-significant digit
            y //= base
        digits.extend(coeffs)
    return np.array(digits, dtype=int)

def gen_par(q):
    """
    Generate public parameters for Dual-GSW.
    Returns tuple: (q, p, m, n, n0, alpha, sigma, L)
    """
    n = lam * 2
    p = 257 # plaintext modulus
    k = math.ceil(math.log2(q))
    m = 10*n

    # Randomly choose n0 within bounds
    upperLimit = int(m/2 - math.ceil(math.sqrt(lam*m / 2)))
    n0 = random.randint(0, upperLimit)

    # Ensure matrix sizes are large enough for GSW
    if m-n0 <= n*k+2*lam:
        m = n*k + 2*lam+n0+1

    alpha = 0.001 # error rate parameter
    alphaQFloat = 0.5
    sigma = 1.0 # standard deviation for Gaussian error
    return q, p, m, n, n0, alpha, sigma, L


def kgen(q):
    """
    Key generation for Dual-GSW.
    Outputs secret key sk and public key pk.
    """
    par = gen_par(q)
    q, p, m, n, n0, alpha, sigma, L = par

    A = sample_uniform_matrix(n, m, q)
    s = sample_matrix_p(m, 1) # secret key vector

    # Compute s^T * A^T mod q
    As = np.matmul(s.T, A.T)%q

    # Public key: vertically stack A^T and As
    B = np.vstack([A.T, As])

    pk = (par, B)
    sk = s
    return sk, pk


def enc(pk, mu):
    """
    Encrypt a plaintext mu using Dual GSW.
    pk: public key
    mu: plaintext integer in [0, p-1]
    Returns ciphertext matrix C.
    """
    par = pk[0]
    B = pk[1]
    q, p, m, n, n0, alpha, sigma, L = par
    k = math.ceil(math.log2(q))

    M = k * (m + 1)
    S = sample_uniform_matrix(n, M, q) # random matrix for masking
    E = sample_error_matrix(m + 1, M, sigma, q) # small error matrix

    BS = np.matmul(B, S) % q        # B*S mod q
    G = gadget_matrix(m + 1, k, q)  # gadget matrix
    Gmu = G*mu                      # embed plaintext
    sum = (BS + Gmu) % q
    C = (sum + E)% q                # add noise
    return C


def dec(par, sk, ct):
    """
    Decrypt a ciphertext ct using Dual-GSW.
    Returns plaintext integer mu.
    """
    q, p, m, n, n0, alpha, sigma, L = par
    delta = int(np.round(q/p))

    # Construct "embedding vector" em
    em = np.zeros((m+1, 1), dtype=int)
    em[-1, 0] = 1
    em_delta = delta*em # scaled vector

    # Construct sk_neg = [-sk^T | 1]
    sk_neg = np.concatenate([-sk.T, np.array([[1]])], axis=1)
    Cs = np.matmul(sk_neg, ct)

    # Gadget decomposition of em_delta
    G_neg = gadget_inverse(em_delta, q)
    v = np.matmul(Cs, G_neg) % q

    # Recover plaintext
    mu = int(np.round(v.item() / delta)) % p
    return mu


# Test the implementation
sk, pk = kgen(2**15)
par = pk[0]
q, p, m, n, n0, alpha, sigma, L = par

mu = random.randint(0, p)
ct = enc(pk, mu)
dm = dec(par, sk, ct)

if mu == dm:
    print("Dual GSW decryption works!")
else:
    print("Dual GSW decryption fails!")





