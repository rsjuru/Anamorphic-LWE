package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"

	"gonum.org/v1/gonum/mat"
	"gonum.org/v1/gonum/stat/distuv"
)

// sampleUniformMatrix generates a matrix with dimensions (rows x cols),
// where each entry is sampled uniformly at random from the integers {0, 1, ..., q-1}.
// The result is returned as a *mat.Dense matrix of float64 values.
func sampleUniformMatrix(rows, cols, q int) *mat.Dense {
	// Create a slice to hold the matrix data (row-major order)
	data := make([]float64, rows*cols)

	// Initialize a new random number generator with the current time as seed
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Fill the matrix data with random values in the range [0, q)
	for i := range data {
		data[i] = float64(rng.Intn(q))
	}

	// Construct and return the matrix using Gonum's mat.NewDense
	return mat.NewDense(rows, cols, data)
}

// sampleErrorMatrix generates a matrix of dimensions (rows x cols)
// where each entry is a small "error" value sampled from a discrete Gaussian (normal) distribution
// centered at 0 with standard deviation alpha*q. Each value is reduced modulo q.
// This simulates the noise typically used in Learning With Errors (LWE) encryption schemes.
func sampleErrorMatrix(rows, cols int, alpha float64, q int) *mat.Dense {
	// Allocate a slice to hold the matrix data in row-major order
	data := make([]float64, rows*cols)

	// Compute the standard deviation of the error distribution
	stdDev := alpha * float64(q)

	// Define the normal distribution N(0, stdDev)
	normal := distuv.Normal{
		Mu:    0,                                               // mean 0
		Sigma: stdDev,                                          // standard deviation = alpha * q
		Src:   rand.New(rand.NewSource(time.Now().UnixNano())), // random source
	}

	// Sample each element from the normal distribution, round to nearest int,
	// then reduce modulo q to ensure the result is in [0, q)
	for i := range data {
		sample := int(math.Round(normal.Rand()))
		data[i] = float64((sample%q + q) % q) // ensure non-negative modulo
	}

	// Construct and return the resulting matrix
	return mat.NewDense(rows, cols, data)
}

// gadgetMatrix generates a "gadget matrix" G of size (n x n*k).
// This matrix is constructed as G = I_n ⊗ g, where:
// - I_n is the identity matrix of size n
// - g = [1, 2, 4, ..., 2^{k-1}] is a binary powers vector (mod q)
// The resulting matrix G helps in bit decomposition and is used in advanced lattice cryptography.
func gadgetMatrix(n, k, q int) *mat.Dense {
	// Step 1: Create gadget vector g = [1, 2, 4, ..., 2^{k-1}] mod q
	g := make([]float64, k)
	for i := 0; i < k; i++ {
		g[i] = float64((1 << i) % q) // 1 << i is 2^i
	}

	// Step 2: Construct G = I_n ⊗ g (Kronecker product of I_n and g)
	// Resulting matrix G has shape (n x n*k)
	// Each row i has the gadget vector g starting at column i*k
	G := mat.NewDense(n, n*k, nil)
	for i := 0; i < n; i++ {
		for j := 0; j < k; j++ {
			G.Set(i, i*k+j, g[j])
		}
	}

	return G
}

// calculateSMatrix constructs a matrix S = I_l ⊗ Sk, where:
// - Sk is a special k × k matrix using bitwise information from q
// - I_l is the identity matrix of size l × l
// The resulting S matrix has shape (l*k) × (l*k) and is used in the anamorphic decryption process.
func calculateSMatrix(k, l, q int) *mat.Dense {
	// Step 1: Create a vector qBits containing the k least significant bits of q
	qBits := make([]float64, k)
	for i := 0; i < k; i++ {
		qBits[i] = float64((q >> i) & 1) // Extract i-th bit of q
	}

	// Step 2: Construct the Sk matrix (k x k)
	// Each row i has:
	// - -1 at (i, i-1) if i > 0
	// - 2 at (i, i) if i < k-1
	// - qBits[i] at the last column (i, k-1)
	Sk := mat.NewDense(k, k, nil)
	for i := 0; i < k; i++ {
		if i > 0 {
			Sk.Set(i, i-1, -1)
		}
		if i < k-1 {
			Sk.Set(i, i, 2)
		}
		Sk.Set(i, k-1, qBits[i])
	}

	// Step 3: Create the identity matrix I_l (l x l)
	I := mat.NewDense(l, l, nil)
	for i := 0; i < l; i++ {
		I.Set(i, i, 1)
	}

	// Step 4: Compute the Kronecker product S = I_l ⊗ Sk
	// This creates a block diagonal matrix where each block is Sk
	S := mat.NewDense(l*k, l*k, nil)
	for i := 0; i < l; i++ {
		for j := 0; j < l; j++ {
			scalar := I.At(i, j)
			for r := 0; r < k; r++ {
				for c := 0; c < k; c++ {
					val := scalar * Sk.At(r, c)
					S.Set(i*k+r, j*k+c, val)
				}
			}
		}
	}

	return S
}

// genParameters generates the LWE parameter set based on a security parameter lam (λ).
// Optionally, a modulus q can be provided as an argument. If not provided, q defaults to 2^15.
func genParameters(lam int, qOptional ...int) ParameterSet {
	// Set default value for q as 2^15 if not provided
	q := 1 << 15 // q = 32768

	if len(qOptional) > 0 {
		q = qOptional[0] // Use the provided q if available
	}

	// Set l = 4 * λ (dimension of message vectors)
	l := 4 * lam

	// Compute k as the bit-length of q (i.e., log₂(q))
	k := int(math.Ceil(math.Log2(float64(q))))

	// Set dimension n = 2lk + 2λ
	n := 2*l*k + 2*lam

	// Set number of samples m = (n + l)k + 2λ
	m := (n+l)*k + 2*lam

	// Set plaintext modulus p
	p := 5

	// Compute noise parameter α = 1 / (2q)
	alpha := 1.0 / (2.0 * float64(q))

	// Return the parameters as a ParameterSet struct
	return ParameterSet{
		q:     q,
		p:     p,
		n:     n,
		m:     m,
		l:     l,
		alpha: alpha,
	}
}

// PublicKey structure using mat.Dense
type PublicKey struct {
	Params ParameterSet
	A      *mat.Dense
	U      *mat.Dense
}

type ParameterSet struct {
	q     int
	p     int
	n     int
	m     int
	l     int
	alpha float64
}

// kgen generates a secret key (S) and a public key (A, U) for the LWE-based cryptosystem.
// Inputs:
//   - lam: security parameter (λ)
//   - q: modulus
// Outputs:
//   - *mat.Dense: secret key matrix S
//   - PublicKey: struct containing parameters, matrix A, and matrix U (transposed)

func kgen(lam, q int) (*mat.Dense, PublicKey) {
	// Generate parameter set from lambda and q
	par := genParameters(lam, q)
	qVal, n, m, l, alpha := par.q, par.n, par.m, par.l, par.alpha

	// Sample matrix A uniformly at random from Z_q^{n x m}
	A := sampleUniformMatrix(n, m, qVal)

	// Sample secret matrix S uniformly from Z_q^{n x l}
	S := sampleUniformMatrix(n, l, qVal)

	// Sample error matrix E from discrete Gaussian with stddev alpha*q over Z_q^{l x m}
	E := sampleErrorMatrix(l, m, alpha, qVal)

	// Compute A^T
	var AT mat.Dense
	AT.CloneFrom(A.T())

	// Compute A^T * S
	var ATS mat.Dense
	ATS.Mul(&AT, S)

	// Transpose error matrix E to match dimensions
	var ET mat.Dense
	ET.CloneFrom(E.T())

	// Compute U = A^T * S + E^T
	var U mat.Dense
	U.Add(&ATS, &ET)

	// Reduce U modulo q element-wise
	modMatrix(&U, q)

	// Transpose U for storage in public key (so A: n x m, U: m x l)
	var Ut mat.Dense
	Ut.CloneFrom(U.T())

	// Return secret key and public key
	return S, PublicKey{
		Params: par,
		A:      A,
		U:      &Ut,
	}
}

// modMatrix reduces all elements of the input matrix modulo q, in-place.
// Inputs:
//   - m: pointer to the matrix to be modified
//   - q: modulus
func modMatrix(m *mat.Dense, q int) {
	r, c := m.Dims() // Get number of rows and columns

	// Iterate over every element of the matrix
	for i := 0; i < r; i++ {
		for j := 0; j < c; j++ {
			// Get the integer value of the element at (i, j)
			val := int(m.At(i, j)) % q

			// Ensure the result is in [0, q-1] by adding q if val is negative
			if val < 0 {
				val += q
			}

			// Set the reduced value back to the matrix
			m.Set(i, j, float64(val))
		}
	}
}

// modVec reduces all elements of the input vector modulo q, in-place.
// Inputs:
//   - v: pointer to the vector to be modified
//   - q: modulus
func modVec(v *mat.VecDense, q int) {
	n := v.Len() // Get the length of the vector

	// Iterate through each element
	for i := 0; i < n; i++ {
		// Compute value modulo q, ensuring result is in [0, q-1]
		val := int(v.AtVec(i)) % q
		if val < 0 {
			val += q
		}
		// Set the reduced value back into the vector
		v.SetVec(i, float64(val))
	}
}

// enc performs encryption using the public key (pk), a message vector mu, and moduli p and q.
// Returns ciphertext components c0 and c1.
// Inputs:
//   - pk: public key containing matrices A and U
//   - mu: message vector (with entries in {0, 1, ..., p-1})
//   - p: plaintext modulus
//   - q: ciphertext modulus
func enc(pk PublicKey, mu *mat.VecDense, p, q int) (*mat.Dense, *mat.Dense) {
	A := pk.A // Matrix A from public key
	U := pk.U // Matrix U = (A^T * S + E^T)^T from public key
	n, m := A.Dims()
	l := mu.Len()

	// Step 1: Sample a random binary vector r of size m×1
	rand.Seed(time.Now().UnixNano())
	rData := make([]float64, m)
	for i := range rData {
		rData[i] = float64(rand.Intn(2)) // Random bit: 0 or 1
	}
	r := mat.NewDense(m, 1, rData)

	// Step 2: Compute delta = round(q/p) for message scaling
	delta := int(math.Round(float64(q) / float64(p)))

	// Step 3: Scale mu by delta and reduce modulo q → mu_q = (delta * mu) mod q
	mu_q := mat.NewVecDense(l, nil)
	for i := 0; i < l; i++ {
		val := int(mu.AtVec(i)) * delta % q
		if val < 0 {
			val += q
		}
		mu_q.SetVec(i, float64(val))
	}

	// Step 4: Compute c0 = A * r mod q
	c0 := mat.NewDense(n, 1, nil)
	c0.Mul(A, r)
	modMatrix(c0, q)

	// Step 5: Compute c1 = U * r + mu_q mod q
	tmp := mat.NewDense(l, 1, nil)
	tmp.Mul(U, r)

	for i := 0; i < l; i++ {
		val := int(tmp.At(i, 0)) + int(mu_q.AtVec(i))
		val %= q
		if val < 0 {
			val += q
		}
		tmp.Set(i, 0, float64(val))
	}
	c1 := tmp

	return c0, c1
}

// dec decrypts a ciphertext (ct) using the secret key sk.
// Inputs:
//   - sk: secret key matrix S (n × l)
//   - ct: ciphertext as an array [c0, c1]
//   - p: plaintext modulus
//   - q: ciphertext modulus
//
// Returns:
//   - m: recovered plaintext vector of length l
func dec(sk *mat.Dense, ct [2]*mat.Dense, p, q int) *mat.VecDense {
	S := sk                // Secret key matrix (n × l)
	c0, c1 := ct[0], ct[1] // Ciphertext components

	_, l := S.Dims() // l = length of message vector

	// Step 1: Compute delta = round(q / p)
	delta := int(math.Round(float64(q) / float64(p)))

	// Step 2: Compute Sᵗ * c0
	var St mat.Dense
	St.CloneFrom(S.T()) // Transpose of S (l × n)

	var St_c0 mat.Dense
	St_c0.Mul(&St, c0) // Matrix multiplication (l × 1)
	modMatrix(&St_c0, q)

	// Step 3: Subtract Sᵗ * c0 from c1: diff = c1 - Sᵗ * c0 mod q
	var diff mat.Dense
	diff.Sub(c1, &St_c0)
	modMatrix(&diff, q)

	// Step 4: Recover m by rounding and scaling down by delta
	m := mat.NewVecDense(l, nil)
	for i := 0; i < l; i++ {
		val := int(math.Round(diff.At(i, 0)/float64(delta))) % p
		if val < 0 {
			val += p
		}
		m.SetVec(i, float64(val))
	}

	return m
}

// agen generates the key components for the advanced encryption scheme.
// Inputs:
//   - lam: security parameter lambda
//   - q: modulus (optional parameter, passed explicitly here)
//
// Returns:
//   - S: secret key matrix
//   - PublicKey: struct containing parameters and matrices A, U
//   - [2]*mat.Dense: ciphertext-like matrices C and D used in key generation
//   - RC: random matrix used in construction
func agen(lam, q int) (*mat.Dense, PublicKey, [2]*mat.Dense, *mat.Dense) {
	// Generate system parameters based on lam and q
	par := genParameters(lam, q)
	q, n, m, l, alpha := par.q, par.n, par.m, par.l, par.alpha
	k := int(math.Ceil(math.Log2(float64(q)))) // bit-length of q

	// Construct gadget matrix G of size (l x l*k)
	G := gadgetMatrix(l, k, q)

	// bar_m is the extended dimension l*k + 2*lam
	bar_m := l*k + 2*lam

	// Sample a uniform random matrix barC of size (l x bar_m)
	barC := sampleUniformMatrix(l, bar_m, q)

	// Sample random matrix RC with entries in {-1, 0, 1} of size (bar_m x l*k)
	RCdata := make([]float64, bar_m*l*k)
	for i := range RCdata {
		RCdata[i] = float64(rand.Intn(3) - 1) // random values in {-1,0,1}
	}
	RC := mat.NewDense(bar_m, l*k, RCdata)

	// Compute right = (barC * RC + G) mod q
	var right mat.Dense
	right.Mul(barC, RC)  // barC * RC
	right.Add(&right, G) // + G
	modMatrix(&right, q) // mod q

	// Horizontally stack barC and right to form C: size (l x (bar_m + l*k))
	C := hstack(barC, &right)

	// Sample error matrices B (l x m) and F (m x n) with Gaussian noise scaled by alpha
	B := sampleErrorMatrix(l, m, alpha, q)
	F := sampleErrorMatrix(m, n, alpha, q)

	// Compute A = (Cᵗ * B + Fᵗ) mod q
	var Ct mat.Dense
	Ct.CloneFrom(C.T()) // transpose of C: size ((bar_m + l*k) x l)

	var AB mat.Dense
	AB.Mul(&Ct, B) // Cᵗ * B

	var Ft mat.Dense
	Ft.CloneFrom(F.T()) // transpose of F: size (n x m)

	AB.Add(&AB, &Ft) // Cᵗ * B + Fᵗ
	modMatrix(&AB, q)

	A := &AB

	// Sample secret matrix S of size (n x l) uniformly at random mod q
	S := sampleUniformMatrix(n, l, q)

	// Sample error matrix E (l x m)
	E := sampleErrorMatrix(l, m, alpha, q)

	// Compute U = (Aᵗ * S + Eᵗ) mod q
	var At mat.Dense
	At.CloneFrom(A.T()) // transpose of A: size (m x n)

	var ATS mat.Dense
	ATS.Mul(&At, S) // Aᵗ * S

	var Et mat.Dense
	Et.CloneFrom(E.T()) // transpose of E: size (m x l)

	ATS.Add(&ATS, &Et) // Aᵗ * S + Eᵗ
	modMatrix(&ATS, q)

	var Ut mat.Dense
	Ut.CloneFrom(ATS.T()) // transpose back: size (l x m)

	// Compute D = C * S (l x l*k + bar_m) * (n x l) ??? Actually dims should be checked carefully
	var D mat.Dense
	D.Mul(C, S)

	return S, PublicKey{Params: par, A: A, U: &Ut}, [2]*mat.Dense{C, &D}, RC
}

// hstack horizontally concatenates two matrices (left and right) with the same number of rows.
// It returns a new matrix that has the columns of `left` followed by the columns of `right`.
// Panics if the row dimensions of the two input matrices do not match.
func hstack(left, right *mat.Dense) *mat.Dense {
	// Get dimensions of the left matrix
	r1, c1 := left.Dims()
	// Get dimensions of the right matrix
	r2, c2 := right.Dims()

	// Ensure both matrices have the same number of rows
	if r1 != r2 {
		panic("hstack: row dimensions do not match")
	}

	// Allocate a slice to hold all elements of the concatenated matrix
	data := make([]float64, r1*(c1+c2))

	// Copy elements from the left matrix into the new data slice
	for i := 0; i < r1; i++ {
		for j := 0; j < c1; j++ {
			data[i*(c1+c2)+j] = left.At(i, j)
		}
		// Copy elements from the right matrix after the left matrix columns
		for j := 0; j < c2; j++ {
			data[i*(c1+c2)+c1+j] = right.At(i, j)
		}
	}

	// Create and return a new Dense matrix with combined columns
	return mat.NewDense(r1, c1+c2, data)
}

// aenc performs an augmented encryption using the augmented public key (apk),
// decryption key components (dk), message vector mu, and secondary message vector smu.
// It returns a ciphertext consisting of two matrices representing the encrypted data.
//
// Parameters:
// - apk: augmented public key containing parameters and matrices A, U
// - dk: decryption key components, an array of two matrices [C, D]
// - mu: message vector to encrypt
// - smu: secondary message vector (e.g., for additional data or randomness)
//
// The function samples a random binary vector r, then computes ciphertext components c0 and c1 as:
// c0 = A*r + C^T * s  (mod q)
// c1 = U*r + D^T * s + mu * delta  (mod q)
// where delta = round(q/p) and s = smu scaled by delta.
//
// Returns:
// - [2]*mat.Dense: the ciphertext components c0 and c1.
func aenc(apk PublicKey, dk [2]*mat.Dense, mu, smu *mat.VecDense) [2]*mat.Dense {
	par := apk.Params
	A := apk.A
	U := apk.U
	C := dk[0]
	D := dk[1]
	q := par.q
	p := par.p
	m := par.m
	l := par.l

	// Sample random binary vector r of length m
	rData := make([]float64, m)
	for i := range rData {
		rData[i] = float64(rand.Intn(2))
	}
	r := mat.NewDense(m, 1, rData)

	// Compute delta = round(q / p)
	delta := int(math.Round(float64(q) / float64(p)))

	// Scale mu by delta modulo q
	mu_q := mat.NewVecDense(mu.Len(), nil)
	for i := 0; i < mu.Len(); i++ {
		val := (int(mu.AtVec(i)) * delta) % q
		if val < 0 {
			val += q
		}
		mu_q.SetVec(i, float64(val))
	}

	// Scale secondary message vector smu by delta modulo q
	s := mat.NewVecDense(smu.Len(), nil)
	for i := 0; i < smu.Len(); i++ {
		val := (int(smu.AtVec(i)) * delta) % q
		if val < 0 {
			val += q
		}
		s.SetVec(i, float64(val))
	}

	// Compute c0 = A*r + C^T * s (mod q)
	c0 := mat.NewDense(par.n, 1, nil)
	Ar := mat.NewDense(par.n, 1, nil)
	Ar.Mul(A, r)

	Ct := mat.DenseCopyOf(C.T())
	Cts := mat.NewDense(par.n, 1, nil)
	Cts.Mul(Ct, vectorToDense(s))

	c0.Add(Ar, Cts)
	modMatrix(c0, q)

	// Compute c1 = U*r + D^T * s + mu_q (mod q)
	Ur := mat.NewDense(l, 1, nil)
	Ur.Mul(U, r)

	Dt := mat.DenseCopyOf(D.T())
	Dts := mat.NewDense(l, 1, nil)
	Dts.Mul(Dt, vectorToDense(s))

	c1 := mat.NewDense(l, 1, nil)
	c1.Add(Ur, Dts)
	for i := 0; i < l; i++ {
		v := int(c1.At(i, 0)) + int(mu_q.AtVec(i))
		v %= q
		if v < 0 {
			v += q
		}
		c1.Set(i, 0, float64(v))
	}
	return [2]*mat.Dense{c0, c1}
}

// vectorToDense converts a vector (*mat.VecDense) to a column matrix (*mat.Dense).
//
// Parameters:
// - v: input vector to convert
//
// Returns:
// - *mat.Dense: a column matrix with the same elements as the input vector.
func vectorToDense(v *mat.VecDense) *mat.Dense {
	rows := v.Len()

	// Allocate a slice to hold vector elements as float64 values
	data := make([]float64, rows)

	// Copy elements from the vector to the data slice
	for i := 0; i < rows; i++ {
		data[i] = v.AtVec(i)
	}

	// Create a new Dense matrix with 'rows' rows and 1 column using the copied data
	return mat.NewDense(rows, 1, data)
}

// adec performs augmented decryption on the given ciphertext using the trapdoor key (tk),
// decryption key components (dk), augmented ciphertext (act), public key (pk), and a parameter lam.
//
// Parameters:
// - tk: trapdoor key matrix
// - dk: decryption key components [C, D] as matrices
// - act: augmented ciphertext components [c0, c1]
// - pk: public key containing parameters and matrices
// - lam: security parameter used for splitting the ciphertext vector
//
// Returns:
// - *mat.VecDense: recovered secret vector s after rounding and modular reduction
// - *mat.Dense: error vector e = c0 - C^T * s mod q
//
// The function splits the ciphertext vector, uses the trapdoor to recover a helper vector,
// computes and verifies gadget matrix relations, then reconstructs the secret vector s and error e.
func adec(tk *mat.Dense, dk, act [2]*mat.Dense, pk PublicKey, lam int) (*mat.VecDense, *mat.Dense) {
	c0 := act[0]
	q, p := float64(pk.Params.q), float64(pk.Params.p)
	l := pk.Params.l
	k := int(math.Ceil(math.Log2(q)))
	C := dk[0]

	// Calculate split index for slicing c0 into two parts
	splitIndex := l*k + 2*lam

	// Split c0 into c0_part1 (first splitIndex rows) and c0_part2 (remaining rows)
	c0_part1 := c0.Slice(0, splitIndex, 0, 1).(*mat.Dense)
	c0_part2 := c0.Slice(splitIndex, c0.RawMatrix().Rows, 0, 1).(*mat.Dense)

	// Compute c0_diff = c0_part2 - R^T * c0_part1
	tkT := mat.Dense{}
	tkT.CloneFrom(tk.T()) // transpose trapdoor matrix
	tmp := mat.NewDense(tk.RawMatrix().Cols, 1, nil)
	tmp.Mul(&tkT, c0_part1)
	c0_diff := mat.NewDense(tmp.RawMatrix().Rows, 1, nil)
	c0_diff.Sub(c0_part2, tmp)
	modMatrix(c0_diff, pk.Params.q)

	// Generate gadget matrix G and matrix S based on parameters l, k, q
	G := gadgetMatrix(l, k, pk.Params.q)
	S := calculateSMatrix(k, l, pk.Params.q)

	// For debugging: check that G*S mod q is zero matrix
	check := mat.NewDense(G.RawMatrix().Rows, S.RawMatrix().Cols, nil)
	check.Mul(G, S)
	modMatrix(check, pk.Params.q)
	// fmt.Println("G*S mod q == 0:", mat.Norm(check, 1) == 0)

	// Compute diff_T = S^T * c0_diff mod q
	ST := mat.Dense{}
	ST.CloneFrom(S.T())
	diff_T := mat.NewDense(ST.RawMatrix().Rows, c0_diff.RawMatrix().Cols, nil)
	diff_T.Mul(&ST, c0_diff)
	modMatrix(diff_T, pk.Params.q)

	// Compute Gs = c0_diff - diff_T mod q
	Gs := mat.NewDense(c0_diff.RawMatrix().Rows, 1, nil)
	Gs.Sub(c0_diff, diff_T)
	modMatrix(Gs, pk.Params.q)

	// Recover s by taking every k-th element of Gs (corresponds to secret vector)
	sLen := l
	sData := make([]float64, sLen)
	for i := 0; i < sLen; i++ {
		sData[i] = Gs.At(i*k, 0)
	}
	s := mat.NewVecDense(sLen, sData)

	// Compute e = c0 - C^T * s mod q
	CT := mat.Dense{}
	CT.CloneFrom(C.T())
	Cs := mat.NewDense(c0.RawMatrix().Rows, 1, nil)
	Cs.Mul(&CT, vectorToDense(s))
	modMatrix(Cs, pk.Params.q)

	e := mat.NewDense(c0.RawMatrix().Rows, 1, nil)
	e.Sub(c0, Cs)
	modMatrix(e, pk.Params.q)

	// Final step: scale and round s by p/q, then reduce modulo p
	sFinal := mat.NewVecDense(sLen, nil)
	for i := 0; i < sLen; i++ {
		val := s.AtVec(i) * p / q
		sFinal.SetVec(i, math.Round(val))
	}
	modVec(sFinal, pk.Params.p)

	return sFinal, e
}

// randomVec generates a random vector of given length with elements in [0, modulus).
//
// Parameters:
// - length: length of the vector
// - modulus: upper bound for random values (exclusive)
//
// Returns:
// - *mat.VecDense: vector with random elements in [0, modulus).
func randomVec(length, modulus int) *mat.VecDense {
	data := make([]float64, length)
	for i := range data {
		data[i] = float64(rand.Intn(modulus))
	}
	return mat.NewVecDense(length, data)
}

// matEqual compares two vectors for equality by checking if they have the same length
// and all corresponding elements are equal when converted to integers.
//
// Parameters:
// - a, b: pointers to mat.VecDense vectors to compare
//
// Returns:
// - bool: true if vectors are equal element-wise, false otherwise
func matEqual(a, b *mat.VecDense) bool {
	if a.Len() != b.Len() {
		return false
	}
	for i := 0; i < a.Len(); i++ {
		if int(a.AtVec(i)) != int(b.AtVec(i)) {
			return false
		}
	}
	return true
}

func main() {
	rand.Seed(time.Now().UnixNano())

	// Generate parameters and keys
	sk, pk := kgen(2, 1<<16)
	par := pk.Params
	q, p, l := par.q, par.p, par.l

	// Generate message
	mu := randomVec(l, p)
	fmt.Printf("Value of q: %d and value of p: %d\n\n", q, p)
	fmt.Printf("Original message: %v\n", mat.Formatted(mu.T()))

	// Encrypt message
	c0, c1 := enc(pk, mu, p, q)
	fmt.Printf("Encrypted message: %v\n", mat.Formatted(c1.T()))

	// Decrypt message
	dm := dec(sk, [2]*mat.Dense{c0, c1}, p, q)
	fmt.Printf("Decrypted message: %v\n", mat.Formatted(dm.T()))
	if matEqual(mu, dm) {
		fmt.Println("LWE decryption works! ✅")
	} else {
		fmt.Println("LWE decryption fails! ❌")
	}

	// Generate anamorphic parameters and keys
	ask, apk, dk, tk := agen(2, 1<<16)
	par = apk.Params
	q, p, l = par.q, par.p, par.l

	// Encrypt and decrypt with anamorphic keys
	mu = randomVec(l, p)
	c0, c1 = enc(apk, mu, p, q)
	dm = dec(ask, [2]*mat.Dense{c0, c1}, p, q)
	fmt.Printf("\nOriginal message; %v\n", mat.Formatted(mu.T()))
	if matEqual(mu, dm) {
		fmt.Println("LWE decryption with anamorphic public/private key works! ✅")
	} else {
		fmt.Println("LWE decryption with anamorhic public/private key fails! ❌")
	}

	// Generate regular and anamorphic messages
	mu = randomVec(l, p)
	s_mu := randomVec(l, p)

	// Anamorphic encryption and decryption
	act := aenc(apk, dk, mu, s_mu)
	adm, error := adec(tk, dk, act, pk, 2)

	fmt.Printf("\nOriginal anamorphic message: %v\n", mat.Formatted(s_mu.T()))
	fmt.Printf("Decrypted anamorphic message: %v\n", mat.Formatted(adm.T()))
	fmt.Printf("Error in anamorphic message: %v\n", mat.Formatted(error.T()))
	if matEqual(adm, s_mu) {
		fmt.Println("Original anamorphic message matches decrypted one! ✅")
		fmt.Println("Anamorphic decryption works! ✅")
	} else {
		fmt.Println("Anamorphic decryption failed! ❌")
	}

	// Decrypt anamorphic ciphertext with regular LWE decryption
	m_am := dec(ask, act, p, q)
	fmt.Printf("\nOriginal message: %v\n,", mat.Formatted(mu.T()))
	fmt.Printf("Message decrypted from anamorphic ciphertext: %v\n", mat.Formatted(m_am.T()))
	if matEqual(mu, m_am) {
		fmt.Println(" Original message matches decrypted from anamorphic ciphertext! ✅")
		fmt.Println("LWE decryption works on anamorphic ciphertext! ✅")
	} else {
		fmt.Println("LWE decryption does not work on anamorphic ciphertext! ❌")
	}

}
