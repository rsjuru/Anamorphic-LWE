package DualRegev

import (
	"anamorphicLWE/matrix"
	"math"
	"math/big"
)

var lam = 2

type ParameterSet struct {
	Q      *big.Int
	P      *big.Int
	N      int
	MBar   int
	Alpha  float64
	StdDev float64
}

type PublicKey struct {
	Params ParameterSet
	A      matrix.BigIntMatrix
	U      matrix.BigIntMatrix
}

// Generates cryptographic parameters for Dual Regev scheme.
func gen_parameters(qOpt ...*big.Int) ParameterSet {

	// Set modulus q
	q := new(big.Int).SetUint64(1 << 15)
	if len(qOpt) > 0 {
		q = qOpt[0]
	}

	// Set plaintext modulus p
	p := new(big.Int).SetUint64(5)

	// Compute high-precision log2(q)
	qFloat := new(big.Float).SetInt(q)
	log2q := new(big.Float).Quo(new(big.Float).SetPrec(256).SetFloat64(math.Log2E), new(big.Float).SetFloat64(math.Log(2)))
	log2q.Mul(log2q, new(big.Float).SetPrec(256).SetInt(q))

	// Compute gadget dimension k = ceil(log2(q))
	k := matrix.Log2BigInt(q)

	// Set dimensions n and mBar
	n := lam
	mBar := n*k + 2*lam

	// Set noise parameter alpha
	alpha := new(big.Float).Quo(big.NewFloat(1.0), new(big.Float).Mul(big.NewFloat(2.0), qFloat))
	stdDev := 1.0
	new_alpha, _ := alpha.Float64()

	// Return parameter set
	return ParameterSet{
		Q:      q,
		P:      p,
		N:      n,
		MBar:   mBar,
		Alpha:  new_alpha,
		StdDev: stdDev,
	}
}

// Generates a key pair for the lattice-based scheme.
func KGen(q *big.Int) (matrix.BigIntMatrix, PublicKey) {
	// Generate cryptographic parameters
	par := gen_parameters(q)

	// Gadget matrix dimension k = ceil(log2(q))
	k := matrix.Log2BigInt(q)

	// Compute matrix width m for A(n x m)
	m := par.MBar + par.N*k

	// Sample public matrix A (uniform in Zq)
	A := matrix.SampleMatrix(par.N, m, q)

	// Sample secret key matrix E (small error)
	E := matrix.SampleError(m, par.N, par.StdDev, q)

	// Compute U = A*E mod q
	U := matrix.MultiplyMatricesParallel(A, E, q)

	// Return secret key and public key
	return E, PublicKey{
		Params: par,
		A:      A,
		U:      U,
	}
}

// Encrypts a plaintext matrix mu using the public key pk.
func Enc(pk PublicKey, mu matrix.BigIntMatrix) [2]matrix.BigIntMatrix {
	par := pk.Params
	A := pk.A
	U := pk.U

	// Compute scaling factor delta = floor(q / p)
	qFloat := new(big.Float).SetInt(par.Q)
	pFloat := new(big.Float).SetInt(par.P)
	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded) // Floor rounding

	// Sample random secret vector s and small errors e0, e1
	s := matrix.SampleMatrix(par.N, 1, par.Q)
	k := matrix.Log2BigInt(par.Q)
	m := par.MBar + par.N*k
	e0 := matrix.SampleError(m, 1, par.StdDev, par.Q)
	e1 := matrix.SampleError(par.N, 1, par.StdDev, par.Q)

	// Scale plaintext: mu_q = delta * mu mod q
	mu_q := matrix.MultiplyMatrixByConstant(mu, deltaRounded, par.Q)

	// Compute c0 = A^T * s + e0 mod q
	AT := matrix.Transpose(A)
	As := matrix.MultiplyMatricesParallel(AT, s, par.Q)
	c0 := matrix.AddMatrices(As, e0, par.Q)

	// Compute c1 = U^T * s + e1 + delta*mu mod q
	UT := matrix.Transpose(U)
	Us := matrix.MultiplyMatricesParallel(UT, s, par.Q)
	Us_e := matrix.AddMatrices(Us, e1, par.Q)
	c1 := matrix.AddMatrices(Us_e, mu_q, par.Q)

	// Return ciphertext pair (c0, c1)
	return [2]matrix.BigIntMatrix{c0, c1}
}

// Decrypts a ciphertext using the secret key sk.
func Dec(par ParameterSet, sk matrix.BigIntMatrix, ct [2]matrix.BigIntMatrix) matrix.BigIntMatrix {
	c0, c1 := ct[0], ct[1]

	// Compute scaling factor delta = q / p
	qFloat := new(big.Float).SetInt(par.Q)
	pFloat := new(big.Float).SetInt(par.P)
	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaHalf := new(big.Float).Quo(delta, big.NewFloat(2))
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded)

	// Compute S^T * c0 mod q
	ST := matrix.Transpose(sk)
	c0_s := matrix.MultiplyMatricesParallel(ST, c0, par.Q)

	// Compute diff = c1 - s^T * c0 mod q
	diff := matrix.SubtractMatricesParallel(c1, c0_s, par.Q)

	// Recover plaintext by scaling diff / delta and rounding
	rows := len(diff)
	cols := len(diff[0])
	result := make(matrix.BigIntMatrix, rows)

	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Convert to big.Float
			tmp := new(big.Float).SetInt(diff[i][j])
			// Add delta/2 for rounding to nearest integer
			tmp.Add(tmp, deltaHalf)
			// Divided by delta
			tmp.Quo(tmp, delta)

			// Convert to integer and reduce modulo p
			rounded := new(big.Int)
			tmp.Int(rounded)
			rounded.Mod(rounded, par.P)
			result[i][j] = rounded
		}
	}
	return result
}

// Generates a public key with a trapdoor for anamorphic dual Regev scheme.
func AGen(q *big.Int) (apk PublicKey, ask matrix.BigIntMatrix, tk matrix.BigIntMatrix) {
	// Generate parameters (same as kgen)
	par := gen_parameters(q)
	k := matrix.Log2BigInt(q)
	m := par.MBar + par.N*k

	// Generate trapdoor matrix R ∈ {−1, 0, 1}
	R := matrix.SampleError(par.MBar, par.N*k, par.StdDev, q)

	// Sample A_bar (n x mbar), a uniform public matrix
	A_bar := matrix.SampleMatrix(par.N, par.MBar, q)

	// Construct a gadget matrix (n x n*k)
	G := matrix.GadgetMatrixParallel(par.N, k, q)

	// right side of A = A_bar*R + G
	AR := matrix.MultiplyMatricesParallel(A_bar, R, q)
	right := matrix.AddMatrices(AR, G, q)

	// Concatenate A_bar and right side to form full A
	A := matrix.HorzConcat(A_bar, right, q)

	// Sample secret error matrix E (m x n)
	E := matrix.SampleError(m, par.N, par.StdDev, q)

	// Compute U = A * E mod q
	U := matrix.MultiplyMatricesParallel(A, E, q)

	// Return public key, secret key and trapdoor.
	return PublicKey{
		Params: par,
		A:      A,
		U:      U,
	}, E, R
}

// Encrypts a plaintext mu with covert message mu_bar using public key apk.
func AEnc(apk PublicKey, mu, mu_bar matrix.BigIntMatrix) [2]matrix.BigIntMatrix {
	par := apk.Params
	A := apk.A
	U := apk.U
	k := matrix.Log2BigInt(par.Q)
	m := par.MBar + par.N*k

	// Sample vectors s, e0 and e1
	s := matrix.SampleError(par.N, 1, 0.5, par.Q)
	e0 := matrix.SampleError(m, 1, par.StdDev, par.Q)
	e1 := matrix.SampleError(par.N, 1, par.StdDev, par.Q)

	// Compute scaling factor delta = floor(q / p)
	qFloat := new(big.Float).SetInt(par.Q)
	pFloat := new(big.Float).SetInt(par.P)
	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded) // Floor rounding

	// Scale plaintext matrices mu and mu_bar by delta
	mu_q := matrix.MultiplyMatrixByConstant(mu, deltaRounded, par.Q)
	mu_bar_q := matrix.MultiplyMatrixByConstant(mu_bar, deltaRounded, par.Q)

	// Embed covert message mu_bar into random mask: s_hat = s + mu_bar_q
	s_hat := matrix.AddMatrices(s, mu_bar_q, par.Q)

	// Compute c0 = A^T * s_hat + e0 mod q
	AT := matrix.Transpose(A)
	As := matrix.MultiplyMatricesParallel(AT, s_hat, par.Q)
	c0 := matrix.AddMatrices(As, e0, par.Q)

	// Compute c1 = U^T * s_hat + e1 + mu_q mod q
	UT := matrix.Transpose(U)
	Us := matrix.MultiplyMatricesParallel(UT, s_hat, par.Q)
	Us_e := matrix.AddMatrices(Us, e1, par.Q)
	c1 := matrix.AddMatrices(Us_e, mu_q, par.Q)

	// Return ciphertext pair [c0, c1]
	return [2]matrix.BigIntMatrix{c0, c1}
}

// Performs anamorphic decryption using the trapdoor R.
func ADec(apk PublicKey, tk, ask matrix.BigIntMatrix, act [2]matrix.BigIntMatrix) matrix.BigIntMatrix {
	c0 := act[0] // first part of ciphertext
	par := apk.Params
	k := matrix.Log2BigInt(par.Q)

	// Split c0 into two part:
	//	- part1 corresponds to A_bar component (columns 0..mBar)
	//	- part2 corresponds to gadget/right-hand component (columns mBar..end)
	splitIndex := par.MBar
	c0_part1 := matrix.SliceBigIntMatrixColRange(c0, 0, splitIndex, 0, 1)
	c0_part2 := matrix.SliceBigIntMatrixColRange(c0, splitIndex, len(c0), 0, 1)

	// Multiply trapdoor matrix transpose with first part
	RT := matrix.Transpose(tk)
	tmp := matrix.MultiplyMatricesParallel(RT, c0_part1, par.Q)

	// Sibtract to isolate gadget contribution
	c0_diff := matrix.SubtractMatricesParallel(c0_part2, tmp, par.Q)

	// Compute S matric used in decryption
	S := matrix.CalculateSMatrixParallel(k, par.N, par.Q)

	// Multiply S^T with difference
	ST := matrix.Transpose(S)
	diff_T := matrix.MultiplyMatricesParallel(ST, c0_diff, par.Q)

	// Subtract projected part to get Gs (essentially a gadget-decomposed vector)
	Gs := matrix.SubtractMatricesParallel(c0_diff, diff_T, par.Q)

	// Recover palintext vector from k-th column of Gs
	s := matrix.RecoverKthColumn(Gs, k, par.N)

	// Scale and round to obtain final plaintext modulo p
	sFinal := matrix.ScaleAndRoundMatrix(s, par.P, par.Q)

	return sFinal
}
