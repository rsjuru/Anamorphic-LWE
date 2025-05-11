import math
import numpy as np
import sympy
from scipy.linalg import block_diag, null_space

lam = 128


def sample_uniform_matrix(rows, cols, q):
    return np.random.randint(0, q-1, size=(rows, cols), dtype=np.int64)


def sample_error_matrix(rows, cols, alpha, q):
    # Sample from Gaussian, then round and mod q
    std_dev = alpha*q
    return np.round(np.random.normal(loc=0, scale=std_dev, size=(rows, cols))).astype(np.int64)

def discrete_gaussian(shape, stddev):
    return np.random.normal(loc=0.0, scale=stddev, size=shape).round().astype(int)


def compute_trapdoor(G, q):
    # Ensure input is a sympy matrix mod q
    G_modq = sympy.Matrix(G) % q

    # Compute nullspace over ℤ_q
    null_basis = G_modq.nullspace()  # list of sympy column vectors

    if not null_basis:
        raise ValueError("Nullspace is empty. G may be full rank modulo q.")

    # Form matrix N from basis vectors
    N = sympy.Matrix.hstack(*null_basis)

    # Compute S = N·Nᵗ mod q
    S = (N * N.T).applyfunc(lambda x: x % q)

    # Return as NumPy array
    return np.array(S).astype(int)


def gen_parameters():
    # Step 1: Choose q anf p ∈ poly(lambda)
    q = lam  # ciphertext modulus
    p = 2 # plaintext modulus

    # Step 2: Compute k = ceil(log2(q))
    k = math.ceil(math.log2(q))

    # Step 3: Choose l ∈ poly(lambda), e.g., l = 4*lambda
    l = 2*lam

    # Step 4: Compute n = 2*l*k+2*lambda
    n = 2*l*k+2*lam

    # Step 5: Compute m ≥ (n+l)*K+2*lambda
    m = (n+l)*k+2*lam

    # Step 6: Choose alpha ∈ (0,1)
    alpha = 0.0001
    print(alpha*q)

    # Return public parameters
    return q, p, n, m, l, alpha


def key_gen():

    par = gen_parameters()
    q, p, n, m, l, alpha = par

    A = sample_uniform_matrix(n, m, q)

    S = sample_uniform_matrix(n, l, q)

    E = sample_error_matrix(l, m, alpha, q)
    print(E)

    At = A.T

    mul = np.matmul(A.T, S).T
    U = (np.matmul(A.T, S) + E.T).T

    pk = (par, A, U)
    sk = S

    return sk, pk


def akey_gen():
    par = gen_parameters()
    q, p, n, m, l, alpha = par

    k = math.ceil(math.log2(q))
    print("k: ", k, " and l: ", l)

    I = np.eye(l)

    v = 2**np.arange(k)

    G = np.kron(I, v) % q

    bar_m = l*k+2*lam
    bar_C = sample_uniform_matrix(l, bar_m, q)

    RC = np.random.randint(-1,2, size=(bar_m, l*k))
    print("RC: ", np.shape(RC))

    right = np.matmul(bar_C, RC) % q
    C = np.hstack((bar_C, (right + G) % q))

    B = discrete_gaussian((l, m), alpha*q)
    F = discrete_gaussian((m,n), alpha*q)

    A_T = (np.matmul(B.T, C) + F) % q

    S = sample_uniform_matrix(n, l, q)
    E = sample_error_matrix(l, m, alpha, q)

    U_T = (np.matmul(A_T, S) + E.T) % q

    D = np.matmul(C, S)

    ask = S
    apk = (par, A_T.T, U_T.T)
    dk = (C, D)

    tk = RC

    return ask, apk, dk, tk


def enc(pk, mu, p, q):

    _, A, U = pk
    n, m = A.shape
    l = mu.shape[0]

    r = np.random.randint(0, 2, size=(m, 1), dtype=np.uint8)
    delta = int(np.round(q/p))

    mu_q = (delta*mu) % q

    c0 = np.matmul(A, r) % q

    print(r.shape)
    c1 = np.matmul(U, r) % q
    print("Before:" ,c1.shape)
    c1 = (c1 + mu_q) % q
    print("After:" ,c1.shape)

    return c0, c1


def aenc(apk, dk, mu, s_mu):
    par, A, U = apk
    C, D = dk

    q, p, n, m, l, alpha = par
    r = np.random.randint(0, 2, size=(m,1), dtype=np.uint8)
    delta = int(np.round(q/p))
    mu_q = (delta*mu) % q
    s = delta*s_mu

    c0 = (np.matmul(A, r) + np.matmul(C.T, s)) % q
    c1 = (np.matmul(U, r) + np.matmul(D.T, s) + mu_q) % q

    return c0, c1


def dec(sk, ct, p, q):
    S = sk
    n, l = S.shape

    c0, c1 = ct

    delta = int(np.round(q/p))
    St_c0 = np.matmul(S.T, c0) % q

    diff = (c1 - St_c0) % q

    print(diff)

    m = np.round(diff/delta).astype(int) % p

    return m


def gadget_matrix(n, k, q):
    """Construct gadget matrix G = I_n ⊗ [1, 2, 4, ..., 2^{k-1}] mod q"""
    g = 2 ** np.arange(k)
    G = np.kron(np.eye(n, dtype=int), g) % q
    return G


def construct_S_from_G(G, q):
    # Convert G to a sympy Matrix for modular arithmetic
    G_modq = sympy.Matrix(G) % q

    # Compute the nullspace of G modulo q
    nullspace = G_modq.nullspace()

    # If the nullspace is empty, raise an error
    if not nullspace:
        raise ValueError("Nullspace is empty, cannot find a valid S matrix.")

    # Construct matrix N from the nullspace basis
    N = sympy.Matrix.hstack(*nullspace)

    # Compute S = N * N^T mod q
    S = (N * N.T) % q

    # Ensure S is a square matrix of size nk x nk
    if S.shape[0] != S.shape[1]:
        raise ValueError(f"Matrix S is not square. Expected shape ({S.shape[0]}, {S.shape[0]}) but got {S.shape}.")

    # Return S as a numpy array
    return np.array(S).astype(int)


def adec(dk, tk, ask, act, par):
    c0, c1 = act
    q, p, n, m, l, alpha = par
    k = int(np.ceil(np.log2(q)))
    C, D = dk

    print("k: ", k, " and l: ", l)

    split_index = l * k + 2 * lam
    #print("Split index: ", split_index)

    # Split y (c0) to y1 and y2
    c0_part1 = c0[:split_index]
    c0_part2 = c0[split_index:]

    #print(np.shape(tk))

    # Calculate y2 - R^T*y1
    c0_diff = c0_part2 - np.matmul(tk.T, c0_part1)

    # Calculate gadget matrix G
    G = gadget_matrix(l, k, q)
    N = null_space(G)

    # Calculate matrix S
    S = construct_S_from_G(G, q)

    # Check that G*S mod q is 0
    result = np.matmul(G, S)
    is_zero = np.all((result) % q == 0)
    print("G*S == 0 mod q?", is_zero)

    # Calculate S^T*(y2 - R^T*y1)
    diff_T = np.matmul(S.T, c0_diff)

    # Calculate inverse of S
    S_inv = np.linalg.inv(S)

    # Calculate e2 - R^T*e1
    error = np.matmul(S_inv, diff_T)

    # Calculate (y2 - R^T*y1) - (e2 - R^T*e1))
    diff = c0_diff - error

    # Calculate s
    s = np.linalg.lstsq(G.T, diff, rcond=None)[0]

    # Calculate e
    e = c0 - np.matmul(C.T, s)

    # Decode s
    s_final = np.round(s*(p/q)).astype(int) % p

    return s_final, e


ask, apk, dk, tk = akey_gen()
par = apk[0]

q, p, n, m, l, alpha = par

mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
s_mu = np.random.randint(0, p, size=(l, 1), dtype=np.int64)

c0, c1 = aenc(apk, dk, mu, s_mu)

dm = dec(ask, (c0, c1), p, q)

if np.array_equal(mu, dm):
    print("Decryption works!")

adm, error = adec(dk, tk, ask, (c0, c1), par)

print(np.shape(adm))
print(l)
print("Anamorphic decryption: ", adm)
print("Anamorphic message: ", s_mu)
if np.array_equal(adm, s_mu):
    print("Anamorphic decryption works!")
else:
    print("Anamorphic decryption failed!")


'''
sk, pk = key_gen()
par = pk[0]
q, p = par[0], par[1]
l = par[4]
m = np.random.randint(0, p, size=(l, 1), dtype=np.int64)
ct = enc(pk, m, p, q)
dec_m = dec(sk, ct, p, q)

m = np.array(m)
dm = np.array(dec_m)

print(m.shape)
print(dm.shape)

print(m)
print(dec_m)

if np.array_equal(m, dm):
    print("Correct encryption!")
else:
    print("Incorrect encryption.")
'''







