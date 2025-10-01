import math
import numpy as np
import random

# Security Parameter
lam = 2
# Multiplicational depth
L = 3


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


def gadget_matrix(n, k, q):
    """
    Construct the gadget matrix G of size n*k, defined as:
    G = I_n ⊗ [1, 2, 4, ..., 2^{k-1}]
    Used in encryption for embedding plaintexts.
    """
    g = 2 ** np.arange(k) # [1, 2, 4, ..., 2^{k-1}
    G = np.kron(np.eye(n, dtype= int), g) % q
    return G

# ----------------- Gadget Functions -----------------

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


# ----------------- Parameter Generation -----------------

def gen_par(q):
    """
    Generate public parameters for Dual-GSW.
    Returns tuple: (q, p, m, n, n0, alpha, sigma, L)
    """
    n = lam * 2
    p = 128 # plaintext modulus
    k = math.ceil(math.log2(q))
    m = 10*n

    # Randomly choose n0 within bounds
    upperLimit = int(m/2 - math.ceil(math.sqrt(lam*m / 2)))
    n0 = random.randint(2, upperLimit)

    # Ensure matrix sizes are large enough for GSW
    if m-n0 <= n*k+2*lam:
        m = n*k + 2*lam+n0+1

    alpha = 1/(2*q) # error rate parameter
    alphaQFloat = 0.5
    sigma = 1.0 # standard deviation for Gaussian error
    return q, p, m, n, n0, alpha, sigma, L


# ----------------- Key Generation -----------------

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


# ----------------- Anamorphic Key Generation -----------------

def agen(q):
    """
    Generate anamorphic keys: ask (secret), apk (public), dk (double key), tk (trapdoor key)
    """
    par = gen_par(q)
    q, p, m, n, n0, alpha, sigma, L = par

    s = sample_matrix_p(m, 1) # secret key
    J = [i for i in range(m) if s[i, 0] == 0] # zero positions
    if len(J) < n0:
        return None, None, None, None

    I = random.sample(J, n0) # select random subset for trapdoor

    # Construct A_hat for selected columns
    A0 = np.random.randint(0, q, size=(n, n0-1))
    t_prime = np.round(sample_error_matrix(n0-1, 1,alpha*q, q)).astype(int)
    eI = np.round(sample_error_matrix(n, 1, alpha*q, q)).astype(int)

    # Combine into A_hat (size n x n0)
    A_hat = np.vstack([A0.T, np.matmul(t_prime.T, A0.T)+eI.T]) % q
    A = sample_uniform_matrix(n, m, q)

    # Assign selected columns
    for j in range(n0-1):
        A[:, I[j]] = A_hat.T[:, j]
    A[:, I[-1]] = A_hat.T[:, -1]

    # Construct trapdoor vector t
    t = np.zeros(m, dtype=int)
    for j in range(n0-1):
        t[I[j]] = -t_prime[j, 0]   # index explicitly
    t[I[-1]] = 1

    # Construct B for public key
    As = np.matmul(s.T, A.T) % q
    B = np.vstack([A.T, As])

    apk = par, B
    ask = s
    dk = I
    tk = t.reshape(-1, 1) # column vector
    return ask, apk, dk, tk


# ----------------- Encryption -----------------

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


# ----------------- Anamorphic Encryption -----------------

def aenc(apk, dk, mu, mu_hat):
    """
    Anamorphic encryption using trapdoor dk and two plaintexts mu, mu_hat.
    Returns ciphertext matrix C.
    """
    par = apk[0]
    B = apk[1]
    q, p, m, n, n0, alpha, sigma, L = par
    k = math.ceil(math.log2(q))
    M = k * (m + 1)

    S = sample_error_matrix(n,M, alpha*q, q)
    E = sample_error_matrix(m+1, M, sigma, q)

    # Construct diagonal matrix J with mu_hat on dk indices
    J = np.zeros((m+1, m+1), dtype=int)
    for i in range(m+1):
        for j in range(m+1):
            if i == j and i in dk:
                J[i, j] = mu_hat
            elif i == j and i not in dk:
                J[i, j] = mu

    g = 2 ** np.arange(k)  # [1, 2, 4, ..., 2^{k-1}
    Jg = np.kron(J, g.T) # Kronecker product
    C = (np.matmul(B, S) + Jg + E) % q
    return C


# ----------------- Decryption -----------------

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


# ----------------- Anamorphic Decryption -----------------

def adec(par, dk, tk, ask, act):
    """
    Anamorphic decryption using trapdoor tk.
    Returns mu_hat ∈ Z_p.
    """
    q, p, m, n, n0, alpha, sigma, L = par
    delta = int(np.round(q/p))

    e_hat = np.zeros((m+1, 1), dtype=np.int64)
    e_hat[dk[-1], 0] = 1 # embedding unit vector

    delta_ehat = delta*e_hat
    Ginv = gadget_inverse(delta_ehat, q)

    t_row = np.concatenate([tk.T, np.array([[0]])], axis=1)
    rowC = np.matmul(t_row, act) % q

    # Convert 1x1 result to scalar
    nu = int((np.matmul(rowC, Ginv) % q).item())

    mu_hat = int(np.round(nu / delta)) % p

    return mu_hat


# ----------------- Testing -----------------

# Regular dual GSW encryption/decryption test
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

# Anamorphic dual GSW encryption/decryption tests
ask, apk, dk, tk = agen(2**15)
par = apk[0]
q, p, m, n, n0, alpha, sigma, L = par

mu = random.randint(0, p)
mu_hat = random.randint(0, p)
act = aenc(apk, dk, mu, mu_hat)
dm = dec(par, ask, act)
adm = adec(par, dk, tk, ask, act)

if mu == dm:
    print("Dual GSW decryption works for anamorphic ciphertext!")
else:
    print("Dual GSW decryption fails for anamorphic ciphertext!")

if mu_hat == adm:
    print("Anamorphic Dual GSW decryption works!")
else:
    print("Anamorphic Dual GSW decryption fails!")





