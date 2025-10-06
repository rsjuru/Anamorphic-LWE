package PrimalRegev

import (
	"anamorphicLWE/matrix"
	"math/big"
)

// Security parameter
const lam = 2

// Structure for cryptographic parameters
type ParameterSet struct {
	Q     *big.Int
	P     *big.Int
	N     int
	M     int
	L     int
	Alpha float64
}

// Structure for public key
type PublicKey struct {
	Params ParameterSet
	A      matrix.BigIntMatrix
	U      matrix.BigIntMatrix
}

// Generates a set of cryptographic parameters for primal Regev scheme.
func genParameters(qOpt ...*big.Int) ParameterSet {
	// Set default q to 2^15 as a big.Int
	q := new(big.Int).SetUint64(1 << 15)

	// If a custom q is provided in qOpt, override the default
	if len(qOpt) > 0 {
		q = qOpt[0]
	}

	// Set plaintext modulus p
	p := big.NewInt(5)

	// Compute k as the base-2 logarithm of q
	k := matrix.Log2BigInt(q)

	// Define dimensions l, n and m
	l := 4 * lam
	n := 2*l*k + 2*lam
	m := (n+l)*k + 2*lam

	// Return parameters
	return ParameterSet{Q: q, P: p, N: n, M: m, L: l, Alpha: 0.5}
}

// Generates a public/private key pair for primal Regev cryptosystem.
func KGen(q *big.Int) (PublicKey, matrix.BigIntMatrix) {
	// Generate cryptographic parameters
	par := genParameters(q)

	// Sample a random matrix A (n x m) with entries mod q
	A := matrix.SampleMatrix(par.N, par.M, par.Q)

	// Sample a secret matrix S (n x l) with entries mod q
	S := matrix.SampleMatrix(par.N, par.L, par.Q)

	// Sample an error matrix E (l x m) from Gaussian error distribution
	E := matrix.SampleError(par.L, par.M, par.Alpha, par.Q)

	// Compute A^T * S mod q
	AT := matrix.Transpose(A)
	ATS := matrix.MultiplyMatricesParallel(AT, S, par.Q)

	// Compute U = ATS + E mod q
	ET := matrix.Transpose(E)
	U := matrix.Transpose(matrix.AddMatrices(ATS, ET, par.Q))

	// Return public and secret key
	return PublicKey{Params: par, A: A, U: U}, S
}

// Encrypts a message mu using the public key pk.
func Enc(pk PublicKey, mu matrix.BigIntMatrix) [2]matrix.BigIntMatrix {
	par := pk.Params

	// Sample a small random vector r (m x 1) with entries in {0,1}
	r := matrix.SampleMatrix(par.M, 1, big.NewInt(2))

	// Compute delta = q / p as a big.Float and convert to big.Int
	qF := new(big.Float).SetInt(par.Q)
	pF := new(big.Float).SetInt(par.P)
	delta := new(big.Float).Quo(qF, pF)
	deltaInt := new(big.Int)
	delta.Int(deltaInt)

	// Scale the message mu by delta and reduce mod q
	mu_q := matrix.MultiplyMatrixByConstant(mu, deltaInt, par.Q)

	// Compute c0 = A * r mod q
	c0 := matrix.MultiplyMatricesParallel(pk.A, r, par.Q)

	// Compute c1 = U*r + delta*mu mod q
	c1 := matrix.AddMatrices(matrix.MultiplyMatricesParallel(pk.U, r, par.Q), mu_q, par.Q)

	// Return ciphertexts (c0, c1)
	return [2]matrix.BigIntMatrix{c0, c1}
}

// Decrypts a ciphertext ct using the secret key sk.
func Dec(par ParameterSet, sk matrix.BigIntMatrix, ct [2]matrix.BigIntMatrix) matrix.BigIntMatrix {
	// Compute delta = q / p as a big.Float
	qF := new(big.Float).SetInt(par.Q)
	pF := new(big.Float).SetInt(par.P)
	delta := new(big.Float).Quo(qF, pF)

	// Compute half of delta for rounding purposes
	halfDelta := new(big.Float).Quo(delta, big.NewFloat(2))

	// Compute S^T * c0 mod q
	ST := matrix.Transpose(sk)
	c0s := matrix.MultiplyMatricesParallel(ST, ct[0], par.Q)

	// Compute the difference c1 - S^T*c0 mod q
	diff := matrix.SubtractMatricesParallel(ct[1], c0s, par.Q)

	// Prepare the result matrix
	rows, cols := len(diff), len(diff[0])
	result := make(matrix.BigIntMatrix, rows)

	// Recover the original message
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			// Convert diff element to float for scaling and rounding
			tmp := new(big.Float).SetInt(diff[i][j])

			// Add halfDelta for proper rounding
			tmp.Add(tmp, halfDelta)

			// Divide by delta to scale back to the original message space
			tmp.Quo(tmp, delta)

			// Convert to integer
			rounded := new(big.Int)
			tmp.Int(rounded)

			// Reduce mod p to get the final message element
			result[i][j] = rounded.Mod(rounded, par.P)
		}
	}
	return result
}

// Generates an advanced set of matrices for an anamorphic primal Regev.
func AGen(q *big.Int) (PublicKey, matrix.BigIntMatrix, [2]matrix.BigIntMatrix, matrix.BigIntMatrix) {
	// Generate cryptoraphic parameters
	par := genParameters(q)

	// Compute k = log2(q)
	k := matrix.Log2BigInt(par.Q)

	// Generate the gadget matrix G mod q
	G := matrix.GadgetMatrixParallel(par.L, k, par.Q)

	// Compute augmented column dimension for barC
	bar_m := par.L*k + 2*lam

	// Sample a random matrix barC (l x bar_m) mod q
	barC := matrix.SampleMatrix(par.L, bar_m, par.Q)

	// Sample a trapdoor matrix R (m x l*k)
	R := matrix.SampleError(bar_m, par.L*k, 0.5, par.Q)

	// Compute barC * R mod q
	barC_R := matrix.MultiplyMatricesParallel(barC, R, par.Q)

	// Compute right side: barC*R + G mod q
	right := matrix.AddMatrices(barC_R, G, par.Q)

	// Horizontally concatenate barC and right to form C mod q
	C := matrix.HorzConcat(barC, right, par.Q)

	// Sample error matrices B and F for constructing A
	B := matrix.SampleError(par.L, par.M, 0.5, par.Q)
	F := matrix.SampleError(par.M, par.N, 0.5, par.Q)

	// Compute A = C^T*B + F^T mod q
	CT := matrix.Transpose(C)
	CB := matrix.MultiplyMatricesParallel(CT, B, par.Q)
	FT := matrix.Transpose(F)
	A := matrix.AddMatrices(CB, FT, par.Q)

	// Sample secret matrix S (n x l) uniformly from Zq
	S := matrix.SampleMatrix(par.N, par.L, par.Q)

	// Sample error matrix E
	E := matrix.SampleError(par.L, par.M, 0.5, par.Q)

	// Compute U = (A^T * S + E)^T mod q
	AT := matrix.Transpose(A)
	ATS := matrix.MultiplyMatricesParallel(AT, S, par.Q)
	ET := matrix.Transpose(E)
	U := matrix.Transpose(matrix.AddMatrices(ATS, ET, par.Q))

	// Compute D = C * S mod q
	D := matrix.MultiplyMatricesParallel(C, S, par.Q)

	// Return the public key, secret key, double key, and trapdoor key
	return PublicKey{
		Params: par,
		A:      A,
		U:      U,
	}, S, [2]matrix.BigIntMatrix{C, D}, R
}

// Encrypts two messages using anamorphic public key apk and double key dk.
func AEnc(apk PublicKey, dk [2]matrix.BigIntMatrix, mu, smu matrix.BigIntMatrix) [2]matrix.BigIntMatrix {
	par := apk.Params
	A := apk.A
	U := apk.U
	C := dk[0]
	D := dk[1]

	// Compute delta = q / p and convert to integer (floor rounding)
	qFloat := new(big.Float).SetInt(par.Q)
	pFloat := new(big.Float).SetInt(par.P)
	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded) // Floor rounding

	// Sample a small random vector r (m x 1) with entries in {0,1}
	r := matrix.SampleMatrix(par.M, 1, new(big.Int).SetInt64(2))

	// Scale the message mu and anamorphic message smu by delta
	mu_q := matrix.MultiplyMatrixByConstant(mu, deltaRounded, par.Q)
	s := matrix.MultiplyMatrixByConstant(smu, deltaRounded, par.Q)

	// Compute c0 = A*r + C^T * s mod q
	Ar := matrix.MultiplyMatricesParallel(A, r, par.Q)
	CT := matrix.Transpose(C)
	CTs := matrix.MultiplyMatricesParallel(CT, s, par.Q)
	c0 := matrix.AddMatrices(Ar, CTs, par.Q)

	// Compute c1 = U*r + D^T*s + delta*mu mod q
	Ur := matrix.MultiplyMatricesParallel(U, r, par.Q)
	DT := matrix.Transpose(D)
	DTs := matrix.MultiplyMatricesParallel(DT, s, par.Q)
	sum := matrix.AddMatrices(Ur, DTs, par.Q)
	c1 := matrix.AddMatrices(sum, mu_q, par.Q)

	// Return ciphertexts (c0, c1)
	return [2]matrix.BigIntMatrix{c0, c1}
}

// Performs anamorphic decryption of a ciphertext using the trapdoor tk.
func ADec(tk matrix.BigIntMatrix, act [2]matrix.BigIntMatrix, apk PublicKey) matrix.BigIntMatrix {
	// Extract the first component of the ciphertext
	c0 := act[0]

	// Get parameters from the public key
	par := apk.Params

	// Compute k = log2(q)
	k := matrix.Log2BigInt(par.Q)

	// Determine the index to split c0 into two parts
	splitIndex := par.L*k + 2*lam

	// Split c0 into the first part (for trapdoor inversion) and second part
	c0_part1 := matrix.SliceBigIntMatrixColRange(c0, 0, splitIndex, 0, 1)
	c0_part2 := matrix.SliceBigIntMatrixColRange(c0, splitIndex, len(c0), 0, 1)

	// Apply the trapdoor tk to invert the first part of c0
	RT := matrix.Transpose(tk)
	tmp := matrix.MultiplyMatricesParallel(RT, c0_part1, par.Q)

	// Subtract the trapdoor effect from the second part to isolate remaining error
	c0_diff := matrix.SubtractMatricesParallel(c0_part2, tmp, par.Q)

	// Compute matrix S for decoding (related to the gadget matrix)
	S := matrix.CalculateSMatrixParallel(k, par.L, par.Q)
	ST := matrix.Transpose(S)

	// Apply S^T to the differenc to extract the masked message component
	diff_T := matrix.MultiplyMatricesParallel(ST, c0_diff, par.Q)

	// Subtract S^T*diff_T from c0_diff to isolate the gadget matrix contribution
	Gs := matrix.SubtractMatricesParallel(c0_diff, diff_T, par.Q)

	// Recover the kth column correspoinding to the original small message
	s := matrix.RecoverKthColumn(Gs, k, par.L)

	// Return the recovered message
	sFinal := matrix.ScaleAndRoundMatrix(s, par.P, par.Q)

	return sFinal
}
