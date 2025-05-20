import math
import numpy as np
from termcolor import colored

lam = 2


def sample_uniform_matrix(rows, cols, q):
    # Sample random matrix with random values between 0 and q-1
    return np.random.randint(0, q-1, size=(rows, cols), dtype=int)


def sample_error_matrix(rows, cols, alpha, q):
    # Sample from Gaussian, then round and mod q
    std_dev = alpha*q
    return np.round(np.random.normal(loc=0, scale=std_dev, size=(rows, cols))).astype(int)


def gadget_matrix(n, k, q):
    # Construct gadget matrix G = I_n ⊗ [1, 2, 4, ..., 2^{k-1}] mod q
    g = 2 ** np.arange(k)
    G = np.kron(np.eye(n, dtype=int), g) % q
    return G


def calculate_SMatrix(k, l, q):
    q_bits = [(q >> i) & 1 for i in range(k)]  # binary expansion LSB to MSB

    # Generate matrix for Sk
    Sk = np.zeros((k, k), dtype=int)

    # Generate Sk
    for i in range(k):
        if i > 0:
            Sk[i, i - 1] = -1
        if i < k - 1:
            Sk[i, i] = 2
        Sk[i, -1] = q_bits[i]  # last column is (q_0, ..., q_{k-1})

    # Calculate matrix S by calculating I_n ⊗ Sk
    I = np.eye(l, dtype=int)
    S = np.kron(I, Sk)
    return S


def gen_parameters(q=None):
    l = 4 * lam
    if q is None:
        log_l = math.log2(l)
        q = 8192 * 64  # default if not provided
    k = math.ceil(math.log2(q))
    n = 2*l * k + 2*lam
    m = (n + l) * k + 2*lam
    p = 5
    alpha = 1 / (2*q)
    return q, p, n, m, l, alpha


def key_gen(q):
    par = gen_parameters(q)
    q, p, n, m, l, alpha = par

    # Sample uniform matrix A
    A = sample_uniform_matrix(n, m, q)

    # Sample secret uniform matrix S
    S = sample_uniform_matrix(n, l, q)

    # Sample error matrix E
    E = sample_error_matrix(l, m, alpha, q)

    # Calculate matrix U = A^T*S + E^T
    U = (np.matmul(A.T, S) + E.T).T % q

    # Denote public and secret key
    pk = (par, A, U)
    sk = S
    return sk, pk


def akey_gen(q):
    # Generate parameters
    par = gen_parameters(q)
    q, p, n, m, l, alpha = par

    # Calculate value k = log2(q)
    k = math.ceil(math.log2(q))

    # Calculate gadget matrix G
    G = gadget_matrix(l, k, q)

    # Caluclate value bar_m
    bar_m = l*k + 2*lam

    # Sample uniform matrix bar_C (mod q)
    bar_C = sample_uniform_matrix(l, bar_m, q)
    # Sample trapdoor matrix R
    RC = np.random.randint(-1, 2, size=(bar_m, l*k))
    # Calculate right side of the matrix C = bar_C*R + G
    right = (np.matmul(bar_C, RC) + G) % q
    # Calculate matrix C = [bar_C | bar_C*R + G]
    C = np.hstack((bar_C, right)).astype(int)

    # Sample matrices B and F from Gaussian error distribution
    B = sample_error_matrix(l, m, alpha, q)
    F = sample_error_matrix(m, n, alpha, q)

    # Calculate matrix A = C^T*B + F^T (mod q)
    A = (np.matmul(C.T, B) + F.T) % q
    # Sample uniform secret matrix S (mod q)
    S = sample_uniform_matrix(n, l, q)
    # Sample error matrix E
    E = sample_error_matrix(l, m, alpha, q)
    # Calculate matrix U_T = A.T*S + E.T (mod q)
    U_T = (np.matmul(A.T, S) + E.T) % q
    # Calculate matrix D = C*S
    D = np.matmul(C, S)
    # Denote anamorphic secret and public key
    ask = S
    apk = (par, A, U_T.T)
    # Denote double key as C and D
    dk = (C, D)
    # Denote trapdoor key as matrix R
    tk = RC
    return ask, apk, dk, tk


def enc(pk, mu, p, q):

    _, A, U = pk
    n, m = A.shape
    l = mu.shape[0]

    # Sample random vector r
    r = np.random.randint(0, 2, size=(m, 1), dtype=np.uint8)
    # Calculate value delta = q/p
    delta = int(np.round(q/p))

    # Calculate delta*mu (mod q)
    mu_q = (delta*mu) % q

    # Calculate c0 = A*r (mod q)
    c0 = np.matmul(A, r) % q

    # Calculate c1 = U*r + delta*mu (mod q)
    c1 = np.matmul(U, r) % q
    c1 = (c1 + mu_q) % q

    return c0, c1


def aenc(apk, dk, mu, s_mu):
    par, A, U = apk
    C, D = dk
    q, p, n, m, l, alpha = par

    # Sample random vector r
    r = np.random.randint(0, 2, size=(m,1), dtype=np.uint8)
    # Calculate delta = q/p
    delta = int(np.round(q/p))
    # Calculate delta*mu (mod q)
    mu_q = (delta*mu) % q
    # Calculate value s = delta*s_mu
    s = (delta*s_mu) % q

    # Calculate c0 = A*r + C^T*s
    c0 = (np.matmul(A, r) + np.matmul(C.T, s))%q
    # Calculate c1 = U*r 0 D^T*s + delta*mu
    c1 = (np.matmul(U, r) + np.matmul(D.T, s) + mu_q) % q

    return c0, c1


def dec(sk, ct, p, q):
    S = sk
    n, l = S.shape

    c0, c1 = ct

    # Calculate delta = q/p
    delta = int(np.round(q/p))

    # Decrypt message m = (c1 - S^T*c0)/delta (mod p)
    St_c0 = np.matmul(S.T, c0) % q
    diff = (c1 - St_c0) % q
    m = np.round(diff/delta).astype(int) % p

    return m


def adec(dk, tk, ask, act, par):
    c0, c1 = act
    q, p, n, m, l, alpha = par
    k = int(np.ceil(np.log2(q)))
    C, D = dk

    # Calculate splitting index = bar_m
    split_index = l * k + 2 * lam

    # Split y (c0) to y1 and y2
    c0_part1 = c0[:split_index]
    c0_part2 = c0[split_index:]

    # Calculate y2 - R^T*y1
    c0_diff = (c0_part2 - np.matmul(tk.T, c0_part1))

    # Calculate gadget matrix G
    G = gadget_matrix(l, k, q)

    # Calculate S matrix
    S = calculate_SMatrix(k, l, q)

    # Check that G*S mod q is 0
    result = np.matmul(G, S)
    is_zero = np.all((result) % q == 0)
    # print("G*S == 0 mod q?", is_zero)

    # Calculate S^T*(y2 - R^T*y1) = e2 - R^T*e1
    diff_T = np.matmul(S.T, c0_diff)

    # Calculate G^T*s = (y2 - R^T*y1) - (e2 - R^T*e1)
    Gs = (c0_diff - diff_T)

    # Get s from Gs
    s = Gs[::k]
    # Calculate e
    e = (c0 - np.matmul(C.T, s)%q)
    s_final = np.round(s * (p / q)).astype(int) % p

    return s_final, e

'''
# Generate parameters and keys
sk, pk = key_gen()
par = pk[0]
q, p, n, m, l, alpha = par

# Generate message
mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
print("Value of q: ", q, " and value of p: ", p)
print("Original message: ", mu.T)

# Encrypt message
ct = enc(pk, mu, p, q)
print("Encrypted message: ", ct[1].T)

# Decrypt message
dm = dec(sk, ct, p, q)
print("Decrypted message: ", dm.T)

# Check that decryption works
if np.array_equal(mu, dm):
    print(colored("LWE decryption works!", "green"))
else:
    print(colored("LWE decryption fails!", "red"))

# Generate anamorphic parameters and keys
ask, apk, dk, tk = akey_gen()
par = apk[0]
q, p, n, m, l, alpha = par

# Generate regular and anamorphic messages
mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
s_mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
# Anamorphic encryption and decryption
c0, c1 = aenc(apk, dk, mu, s_mu)
adm, e = adec(dk, tk, ask, (c0, c1), par)

print("Original anamorphic message: ", s_mu.T)
print("Decrypted anamorphic message: ", adm.T)

# Check that anamorphic decryption works
if np.array_equal(adm, s_mu):
    print(colored("Original anamorphic message matches the decrypted anamorphic message!", "green"))
    print(colored("Anamorphic decryption works!", "green"))
else:
    print(colored("Anamorphic decryption failed!", "red"))

# Decrypt anamorphic ciphertext with regular LWE decryption
m_am = dec(ask, (c0, c1), p, q)

print("Original message: ", mu.T)
print("Message encrypted from anamorphic ciphertext: ", m_am.T)

# Check that LWE decryption works on anamorphic ciphertext
if np.array_equal(mu, m_am):
    print(colored("Original message matches the message decrypted from anamorphic ciphertext!", "green"))
    print(colored("LWE Decryption works on anamorphic ciphertext!", "green"))
else:
    print(colored("LWE decryption does not work on anamorphic ciphertext!", "red"))
'''