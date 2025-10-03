package dualGSW

import (
	"anamorphicLWE/matrix"
	"math"
	"math/big"
	mrand "math/rand"
	"time"
)

type Parameters struct {
	Q     *big.Int
	P     *big.Int
	M     int
	N     int
	N0    int
	Alpha float64
	Sigma float64
	L     int
}

type PublicKey struct {
	Par Parameters
	B   matrix.BigIntMatrix
}

type AKeySet struct {
	Ask matrix.BigIntMatrix
	Apk PublicKey
	Dk  []int
	Tk  matrix.BigIntMatrix
}

const lambda = 2
const L = 3

// Extracts the first column of a matrix and returns it as a vector
func flattenMatrix(mat matrix.BigIntMatrix) []*big.Int {
	n := len(mat) // number of rows
	res := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		// Copy the value from the first column of each row
		res[i] = new(big.Int).Set(mat[i][0])
	}
	return res
}

func genParameters(q *big.Int) Parameters {
	mrand.Seed(time.Now().UnixNano())

	n := lambda * 2
	p := big.NewInt(256) // plaintext modulus
	k := int(math.Ceil(math.Log2(float64(q.Int64()))))
	m := 10 * n

	upperLimit := int(math.Floor(float64(m)/2.0 - math.Ceil(math.Sqrt(float64(lambda*m)/2.0))))
	if upperLimit < 2 {
		upperLimit = 2
	}

	n0 := mrand.Intn(upperLimit-1) + 2
	if m-n0 <= n*k+2*lambda {
		m = n*k + 2*lambda + n0 + 1
	}

	alpha := 1.0 / (2.0 * float64(q.Int64()))
	sigma := 1.0

	return Parameters{
		Q:     q,
		P:     p,
		M:     m,
		N:     n,
		N0:    n0,
		Alpha: alpha,
		Sigma: sigma,
		L:     L,
	}
}

func KGen(q *big.Int) (sk matrix.BigIntMatrix, pk PublicKey) {
	par := genParameters(q)

	// Sample uniform matrix A (n x m)
	A := matrix.SampleMatrix(par.N, par.M, par.Q)

	// Sample secret vector s (m x 1) from P = {-1, 0, 1}
	s := matrix.SampleMatrixP(par.M, 1)

	// Compute s^T * A^T mod q
	A_T := matrix.Transpose(A)
	s_T := matrix.Transpose(s)
	As := matrix.MultiplyMatricesParallel(s_T, A_T, q)

	// Public key: vertically stack A^T and As
	rowsA := len(A_T)
	rowsAs := len(As)
	cols := len(A_T[0])

	B := make(matrix.BigIntMatrix, rowsA+rowsAs)
	for i := 0; i < rowsA; i++ {
		B[i] = make([]*big.Int, cols)
		copy(B[i], A_T[i])
	}
	for i := 0; i < rowsAs; i++ {
		B[rowsA+i] = make([]*big.Int, cols)
		copy(B[rowsA+i], As[i])
	}

	pk.Par = par
	pk.B = B
	sk = s

	return
}

func AGen(q *big.Int) *AKeySet {
	// Generate parameters
	par := genParameters(q)

	s := matrix.SampleMatrixP(par.M, 1)

	// Find zero positions in s
	J := []int{}
	for i := 0; i < par.M; i++ {
		if s[i][0].Cmp(big.NewInt(0)) == 0 {
			J = append(J, i)
		}
	}

	// if not enough zeros for trapdoor, return failure
	if len(J) < par.N0 {
		return nil
	}

	// Randomly select n0 indices from J
	mrand.Shuffle(len(J), func(i, j int) { J[i], J[j] = J[j], J[i] })
	I := J[:par.N0]

	// Construct A_har (size n x n0)
	// A0: n x (n0-1)
	A0 := matrix.SampleMatrix(par.N, par.N0-1, par.Q)
	tPrime := matrix.SampleError(par.N0-1, 1, 0.5, par.Q)
	eI := matrix.SampleError(par.N, 1, 0.5, par.Q)

	// A_hat = [A0.T; tPrime^T*A0^T + eI^T] mod q
	A0T := matrix.Transpose(A0)
	tPrimeT := matrix.Transpose(tPrime)
	eIT := matrix.Transpose(eI)
	// fmt.Println("Size of A0:", len(A0), "x", len(A0[0]))
	// fmt.Println("Size of tPrimeT:", len(tPrimeT), "x", len(tPrimeT[0]))
	AOtPrime := matrix.MultiplyMatricesParallel(tPrimeT, A0T, par.Q)
	sum := matrix.AddMatrices(AOtPrime, eIT, par.Q)
	A_hat := matrix.AppendRows(A0T, sum)
	A_hatT := matrix.Transpose(A_hat)

	// Random A: n x m
	A := matrix.SampleMatrix(par.N, par.M, par.Q)

	// Assign selected columns from A_hat into A
	for j := 0; j < par.N0; j++ {
		for row := 0; row < par.N; row++ {
			A[row][I[j]] = A_hatT[row][j]
		}
	}

	// Construct trapdoor vector t (m x 1)
	t := make(matrix.BigIntMatrix, par.M)
	for i := 0; i < par.M; i++ {
		t[i] = make([]*big.Int, 1)
		t[i][0] = big.NewInt(0)
	}

	for j := 0; j < par.N0-1; j++ {
		idx := I[j]
		neg := new(big.Int).Neg(tPrime[j][0])
		t[idx][0] = neg
	}
	// last trapdoor index
	t[I[par.N0-1]][0] = big.NewInt(1)

	// build public matrix B
	AT := matrix.Transpose(A)
	sT := matrix.Transpose(s)
	As := matrix.MultiplyMatricesParallel(sT, AT, par.Q)

	B := matrix.AppendRows(AT, As)
	apk := PublicKey{Par: par, B: B}

	return &AKeySet{Ask: s, Apk: apk, Dk: I, Tk: t}
}

func Enc(pk PublicKey, mu *big.Int) matrix.BigIntMatrix {
	par := pk.Par
	k := int(math.Ceil(math.Log2(float64(par.Q.Int64()))))
	M := k * (par.M + 1)

	// Sample random masking matrix S (n x M)
	S := matrix.SampleMatrix(par.N, M, par.Q)

	// Sample small error matrix E ((m+1) x M)
	E := matrix.SampleError(par.M+1, M, par.Sigma, par.Q)

	// Compute BS = B * S mod q
	BS := matrix.MultiplyMatricesParallel(pk.B, S, par.Q)

	// Gadget matrix G od size (m+1) x (m+1)*k
	G := matrix.GadgetMatrixParallel(par.M+1, k, par.Q)

	Gmu := matrix.MultiplyMatrixByConstant(G, mu, par.Q)

	// Sum = (BS + Gmu) mod q
	sum := matrix.AddMatrices(BS, Gmu, par.Q)

	// Add noise: C = (sum + E) mod q
	C := matrix.AddMatrices(sum, E, par.Q)

	return C
}

func AEnc(apk PublicKey, dk []int, mu, muHat *big.Int) matrix.BigIntMatrix {
	par := apk.Par

	logQ := math.Log2(float64(par.Q.Int64()))
	k := int(math.Ceil(logQ))
	M := k * (par.M + 1)

	// S = error matrix (n x M), E = error matrix ((m + 1), M)
	// stddevAlpha := par.alpha * float64(par.q.Int64())
	S := matrix.SampleError(par.N, M, 0.5, par.Q)
	E := matrix.SampleError(par.M+1, M, par.Sigma, par.Q)

	// Build diagonal matrix J with muHat at indices in dk, else mu
	J := make(matrix.BigIntMatrix, par.M+1)
	for i := 0; i < par.M+1; i++ {
		J[i] = make([]*big.Int, par.M+1)
		for j := 0; j < par.M+1; j++ {
			J[i][j] = big.NewInt(0)
			if i == j {
				found := false
				for _, idx := range dk {
					if idx == j {
						J[i][j] = new(big.Int).Set(muHat)
						found = true
						break
					}
				}
				if !found {
					J[i][j] = new(big.Int).Set(mu)
				}
			}
		}
	}

	//g = [1, 2, 4, ..., 2^(k-1)]
	g := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		g[i] = new(big.Int).Lsh(big.NewInt(1), uint(i))
	}

	// Compute Jg = kron(J, g) (size (m+1) x M)
	Jg := make(matrix.BigIntMatrix, par.M+1)
	for i := 0; i < par.M+1; i++ {
		Jg[i] = make([]*big.Int, M)
		for col := 0; col < M; col++ {
			Jg[i][col] = big.NewInt(0) // <- no nils
		}
		for j := 0; j < par.M+1; j++ {
			if J[i][j].Cmp(big.NewInt(0)) != 0 {
				for t := 0; t < k; t++ {
					colIdx := j*k + t
					Jg[i][colIdx].Mul(J[i][j], g[t])
					Jg[i][colIdx].Mod(Jg[i][colIdx], par.Q)
				}
			}
		}
	}

	// fmt.Println("Size of B:", len(apk.B), "x", len(apk.B[0]))
	// fmt.Println("Size of S:", len(S), "x", len(S[0]))
	// C = (B*S + Jg + E) mod q
	BS := matrix.MultiplyMatricesParallel(apk.B, S, par.Q)
	tmp := matrix.AddMatrices(BS, Jg, par.Q)
	C := matrix.AddMatrices(tmp, E, par.Q)

	return C
}

func Dec(par Parameters, sk matrix.BigIntMatrix, ct matrix.BigIntMatrix) *big.Int {

	// delta = round(q/p)
	delta := new(big.Int).Div(par.Q, par.P)

	// Construct embedding vector em of size (m+1) x 1 with last entry = 1
	em := make(matrix.BigIntMatrix, par.M+1)
	for i := 0; i < par.M; i++ {
		em[i] = []*big.Int{big.NewInt(0)}
	}
	em[par.M] = []*big.Int{big.NewInt(1)}

	// em_delta = delta * em
	emDelta := matrix.MultiplyMatrixByConstant(em, delta, par.Q)

	// Construct sk_neg = [-sk^T | 1]
	sk_T := matrix.Transpose(sk)
	sk_neg := make(matrix.BigIntMatrix, len(sk_T))
	for i := range sk_T {
		sk_neg[i] = make([]*big.Int, len(sk_T[i])+1)
		for j := range sk_T[i] {
			tmp := new(big.Int).Neg(sk_T[i][j])
			sk_neg[i][j] = tmp.Mod(tmp, par.Q)
		}
		sk_neg[i][len(sk_T[i])] = big.NewInt(1)
	}

	// Compute Cs = sk_neg * ct mod q
	Cs := matrix.MultiplyMatricesParallel(sk_neg, ct, par.Q)

	// Gadget decomposition of em_delta
	G_neg := matrix.GadgetInverse(flattenMatrix(emDelta), par.Q, 2)

	// fmt.Println("Cs:", len(Cs), "x", len(Cs[0]))
	// fmt.Println("G_neg:", len(G_neg), "x", len(G_neg[0]))

	// nu = Cs * G_neg mod q
	nu := matrix.MultiplyMatricesParallel(Cs, G_neg, par.Q)

	// Recover plaintext: mu = round(nu / delta) mod p
	nuVal := new(big.Int).Set(nu[0][0])
	qdiv := matrix.RoundDiv(nuVal, delta)
	mu := new(big.Int).Mod(qdiv, par.P)

	return mu
}

func ADec(par Parameters, dk []int, tk, ask, act matrix.BigIntMatrix) *big.Int {
	// Compute delta = round(q/p)
	delta := new(big.Int).Div(par.Q, par.P)

	// Construct e_hat vector ((m+1) x 1)
	eHat := make(matrix.BigIntMatrix, par.M+1)
	for i := 0; i < par.M+1; i++ {
		eHat[i] = make([]*big.Int, 1)
		eHat[i][0] = big.NewInt(0)
	}
	// Set embedding unit vector
	eHat[dk[len(dk)-1]][0] = big.NewInt(1)

	// delta * e_hat
	deltae := matrix.MultiplyMatrixByConstant(eHat, delta, par.Q)

	// Gadget inverse
	G_inv := matrix.GadgetInverse(flattenMatrix(deltae), par.Q, 2)

	// Concatenate tk row with 0 to form t_row
	tRow := make(matrix.BigIntMatrix, 1)
	tRow[0] = make([]*big.Int, par.M+1)
	for i := 0; i < par.M; i++ {
		tRow[0][i] = new(big.Int).Set(tk[i][0])
	}
	tRow[0][par.M] = big.NewInt(0)

	// Multiply t_row * act mod q
	rowC := matrix.MultiplyMatricesParallel(tRow, act, par.Q)

	// Multiply rowC * Ginv mod q
	nu := matrix.MultiplyMatricesParallel(rowC, G_inv, par.Q)

	// Convert 1x1 result to scalar
	nu_scalar := nu[0][0]
	qdiv := matrix.RoundDiv(nu_scalar, delta)
	mutHat := new(big.Int).Mod(qdiv, par.P)

	return mutHat
}
