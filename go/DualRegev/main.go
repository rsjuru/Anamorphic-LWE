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

func gen_parameters(qOpt ...*big.Int) ParameterSet {
	q := new(big.Int).SetUint64(1 << 15)
	if len(qOpt) > 0 {
		q = qOpt[0]
	}

	p := new(big.Int).SetUint64(5)

	// High-precision log2(q)
	qFloat := new(big.Float).SetInt(q)
	log2q := new(big.Float).Quo(new(big.Float).SetPrec(256).SetFloat64(math.Log2E), new(big.Float).SetFloat64(math.Log(2)))
	log2q.Mul(log2q, new(big.Float).SetPrec(256).SetInt(q))

	k := matrix.Log2BigInt(q)

	n := lam
	mBar := n*k + 2*lam

	// alpha = 1 / (2q)
	alpha := new(big.Float).Quo(big.NewFloat(1.0), new(big.Float).Mul(big.NewFloat(2.0), qFloat))
	stdDev := 1.0
	new_alpha, _ := alpha.Float64()

	return ParameterSet{
		Q:      q,
		P:      p,
		N:      n,
		MBar:   mBar,
		Alpha:  new_alpha,
		StdDev: stdDev,
	}
}

func KGen(q *big.Int) (matrix.BigIntMatrix, PublicKey) {
	// Generate parameter set
	par := gen_parameters(q)

	k := matrix.Log2BigInt(q)
	m := par.MBar + par.N*k

	// Sample matrix A
	A := matrix.SampleMatrix(par.N, m, q)

	// Sample error matrix E
	E := matrix.SampleError(m, par.N, par.StdDev, q)

	// Compute U = A*E
	U := matrix.MultiplyMatricesParallel(A, E, q)

	return E, PublicKey{
		Params: par,
		A:      A,
		U:      U,
	}
}

func Enc(pk PublicKey, mu matrix.BigIntMatrix) [2]matrix.BigIntMatrix {
	par := pk.Params
	A := pk.A
	U := pk.U

	qFloat := new(big.Float).SetInt(par.Q)
	pFloat := new(big.Float).SetInt(par.P)

	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded) // Floor rounding
	// deltaHalf := new(big.Float).Quo(delta, big.NewFloat(2))

	// Sample s, e0, e1
	s := matrix.SampleMatrix(par.N, 1, par.Q)
	k := matrix.Log2BigInt(par.Q)
	m := par.MBar + par.N*k
	e0 := matrix.SampleError(m, 1, par.StdDev, par.Q)
	e1 := matrix.SampleError(par.N, 1, par.StdDev, par.Q)

	// delta * mu
	mu_q := matrix.MultiplyMatrixByConstant(mu, deltaRounded, par.Q)

	AT := matrix.Transpose(A)
	As := matrix.MultiplyMatricesParallel(AT, s, par.Q)
	c0 := matrix.AddMatrices(As, e0, par.Q)

	UT := matrix.Transpose(U)
	Us := matrix.MultiplyMatricesParallel(UT, s, par.Q)
	Us_e := matrix.AddMatrices(Us, e1, par.Q)
	c1 := matrix.AddMatrices(Us_e, mu_q, par.Q)

	return [2]matrix.BigIntMatrix{c0, c1}
}

func Dec(par ParameterSet, sk matrix.BigIntMatrix, ct [2]matrix.BigIntMatrix) matrix.BigIntMatrix {
	c0, c1 := ct[0], ct[1]

	qFloat := new(big.Float).SetInt(par.Q)
	pFloat := new(big.Float).SetInt(par.P)
	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaHalf := new(big.Float).Quo(delta, big.NewFloat(2))
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded)

	ST := matrix.Transpose(sk)
	c0_s := matrix.MultiplyMatricesParallel(ST, c0, par.Q)
	diff := matrix.SubtractMatricesParallel(c1, c0_s, par.Q)

	rows := len(diff)
	cols := len(diff[0])
	result := make(matrix.BigIntMatrix, rows)

	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Convert to big.Float
			tmp := new(big.Float).SetInt(diff[i][j])
			tmp.Add(tmp, deltaHalf)
			tmp.Quo(tmp, delta)

			rounded := new(big.Int)
			tmp.Int(rounded)
			rounded.Mod(rounded, par.P)
			result[i][j] = rounded
		}
	}
	return result
}

func AGen(q *big.Int) (apk PublicKey, ask matrix.BigIntMatrix, tk matrix.BigIntMatrix) {
	// Generate parameters (same as kgen)
	par := gen_parameters(q)
	k := matrix.Log2BigInt(q)
	m := par.MBar + par.N*k

	// Generate trapdoor matrix R ∈ {−1, 0, 1}
	R := matrix.SampleError(par.MBar, par.N*k, par.StdDev, q)
	A_bar := matrix.SampleMatrix(par.N, par.MBar, q)
	G := matrix.GadgetMatrixParallel(par.N, k, q)

	// right side of A = A_bar*R + G
	AR := matrix.MultiplyMatricesParallel(A_bar, R, q)
	right := matrix.AddMatrices(AR, G, q)
	A := matrix.HorzConcat(A_bar, right, q)
	E := matrix.SampleError(m, par.N, par.StdDev, q)

	U := matrix.MultiplyMatricesParallel(A, E, q)

	return PublicKey{
		Params: par,
		A:      A,
		U:      U,
	}, E, R
}

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

	// Compute delta = round(q / p)
	qFloat := new(big.Float).SetInt(par.Q)
	pFloat := new(big.Float).SetInt(par.P)

	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded) // Floor rounding

	mu_q := matrix.MultiplyMatrixByConstant(mu, deltaRounded, par.Q)
	mu_bar_q := matrix.MultiplyMatrixByConstant(mu_bar, deltaRounded, par.Q)

	s_hat := matrix.AddMatrices(s, mu_bar_q, par.Q)
	AT := matrix.Transpose(A)
	As := matrix.MultiplyMatricesParallel(AT, s_hat, par.Q)
	c0 := matrix.AddMatrices(As, e0, par.Q)

	// Compute c1 = U^T*s_hat + e1 + mu_q
	UT := matrix.Transpose(U)
	Us := matrix.MultiplyMatricesParallel(UT, s_hat, par.Q)
	Us_e := matrix.AddMatrices(Us, e1, par.Q)
	c1 := matrix.AddMatrices(Us_e, mu_q, par.Q)

	return [2]matrix.BigIntMatrix{c0, c1}
}

func ADec(apk PublicKey, tk, ask matrix.BigIntMatrix, act [2]matrix.BigIntMatrix) matrix.BigIntMatrix {
	c0 := act[0]
	par := apk.Params
	k := matrix.Log2BigInt(par.Q)

	splitIndex := par.MBar

	c0_part1 := matrix.SliceBigIntMatrixColRange(c0, 0, splitIndex, 0, 1)
	c0_part2 := matrix.SliceBigIntMatrixColRange(c0, splitIndex, len(c0), 0, 1)

	RT := matrix.Transpose(tk)
	tmp := matrix.MultiplyMatricesParallel(RT, c0_part1, par.Q)
	c0_diff := matrix.SubtractMatricesParallel(c0_part2, tmp, par.Q)

	// G := gadgetMatrix(par.n, k, par.q)
	S := matrix.CalculateSMatrixParallel(k, par.N, par.Q)

	ST := matrix.Transpose(S)
	diff_T := matrix.MultiplyMatricesParallel(ST, c0_diff, par.Q)
	Gs := matrix.SubtractMatricesParallel(c0_diff, diff_T, par.Q)
	s := matrix.RecoverKthColumn(Gs, k, par.N)
	sFinal := matrix.ScaleAndRoundMatrix(s, par.P, par.Q)

	return sFinal
}
