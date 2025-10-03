package PrimalRegev

import (
	"anamorphicLWE/matrix"
	"math/big"
)

const lam = 2

type ParameterSet struct {
	Q     *big.Int
	P     *big.Int
	N     int
	M     int
	L     int
	Alpha float64
}

type PublicKey struct {
	Params ParameterSet
	A      matrix.BigIntMatrix
	U      matrix.BigIntMatrix
}

func genParameters(qOpt ...*big.Int) ParameterSet {
	q := new(big.Int).SetUint64(1 << 15)
	if len(qOpt) > 0 {
		q = qOpt[0]
	}
	p := big.NewInt(5)
	k := matrix.Log2BigInt(q)
	l := 4 * lam
	n := 2*l*k + 2*lam
	m := (n+l)*k + 2*lam
	return ParameterSet{Q: q, P: p, N: n, M: m, L: l, Alpha: 0.5}
}

// Key Generation
func KGen(q *big.Int) (PublicKey, matrix.BigIntMatrix) {
	par := genParameters(q)
	A := matrix.SampleMatrix(par.N, par.M, par.Q)
	S := matrix.SampleMatrix(par.N, par.L, par.Q)
	E := matrix.SampleError(par.L, par.M, par.Alpha, par.Q)
	AT := matrix.Transpose(A)
	ATS := matrix.MultiplyMatricesParallel(AT, S, par.Q)
	ET := matrix.Transpose(E)
	U := matrix.Transpose(matrix.AddMatrices(ATS, ET, par.Q))
	return PublicKey{Params: par, A: A, U: U}, S
}

// Encryption
func Enc(pk PublicKey, mu matrix.BigIntMatrix) [2]matrix.BigIntMatrix {
	par := pk.Params
	r := matrix.SampleMatrix(par.M, 1, big.NewInt(2))

	qF := new(big.Float).SetInt(par.Q)
	pF := new(big.Float).SetInt(par.P)
	delta := new(big.Float).Quo(qF, pF)
	deltaInt := new(big.Int)
	delta.Int(deltaInt)

	mu_q := matrix.MultiplyMatrixByConstant(mu, deltaInt, par.Q)
	c0 := matrix.MultiplyMatricesParallel(pk.A, r, par.Q)
	c1 := matrix.AddMatrices(matrix.MultiplyMatricesParallel(pk.U, r, par.Q), mu_q, par.Q)
	return [2]matrix.BigIntMatrix{c0, c1}
}

// Decryption
func Dec(par ParameterSet, sk matrix.BigIntMatrix, ct [2]matrix.BigIntMatrix) matrix.BigIntMatrix {
	qF := new(big.Float).SetInt(par.Q)
	pF := new(big.Float).SetInt(par.P)
	delta := new(big.Float).Quo(qF, pF)
	halfDelta := new(big.Float).Quo(delta, big.NewFloat(2))

	ST := matrix.Transpose(sk)
	c0s := matrix.MultiplyMatricesParallel(ST, ct[0], par.Q)
	diff := matrix.SubtractMatricesParallel(ct[1], c0s, par.Q)

	rows, cols := len(diff), len(diff[0])
	result := make(matrix.BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			tmp := new(big.Float).SetInt(diff[i][j])
			tmp.Add(tmp, halfDelta)
			tmp.Quo(tmp, delta)
			rounded := new(big.Int)
			tmp.Int(rounded)
			result[i][j] = rounded.Mod(rounded, par.P)
		}
	}
	return result
}

func AGen(q *big.Int) (PublicKey, matrix.BigIntMatrix, [2]matrix.BigIntMatrix, matrix.BigIntMatrix) {
	par := genParameters(q)
	k := matrix.Log2BigInt(par.Q)

	G := matrix.GadgetMatrixParallel(par.L, k, par.Q)

	bar_m := par.L*k + 2*lam

	barC := matrix.SampleMatrix(par.L, bar_m, par.Q)
	R := matrix.SampleError(bar_m, par.L*k, 0.5, par.Q)

	barC_R := matrix.MultiplyMatricesParallel(barC, R, par.Q)
	right := matrix.AddMatrices(barC_R, G, par.Q)

	C := matrix.HorzConcat(barC, right, par.Q)

	B := matrix.SampleError(par.L, par.M, 0.5, par.Q)
	F := matrix.SampleError(par.M, par.N, 0.5, par.Q)

	CT := matrix.Transpose(C)
	CB := matrix.MultiplyMatricesParallel(CT, B, par.Q)
	FT := matrix.Transpose(F)
	A := matrix.AddMatrices(CB, FT, par.Q)

	S := matrix.SampleMatrix(par.N, par.L, par.Q)
	E := matrix.SampleError(par.L, par.M, 0.5, par.Q)

	AT := matrix.Transpose(A)
	ATS := matrix.MultiplyMatricesParallel(AT, S, par.Q)
	ET := matrix.Transpose(E)
	U := matrix.Transpose(matrix.AddMatrices(ATS, ET, par.Q))

	D := matrix.MultiplyMatricesParallel(C, S, par.Q)

	return PublicKey{
		Params: par,
		A:      A,
		U:      U,
	}, S, [2]matrix.BigIntMatrix{C, D}, R
}

func AEnc(apk PublicKey, dk [2]matrix.BigIntMatrix, mu, smu matrix.BigIntMatrix) [2]matrix.BigIntMatrix {
	par := apk.Params
	A := apk.A
	U := apk.U
	C := dk[0]
	D := dk[1]

	qFloat := new(big.Float).SetInt(par.Q)
	pFloat := new(big.Float).SetInt(par.P)

	delta := new(big.Float).Quo(qFloat, pFloat)
	deltaRounded := new(big.Int)
	delta.Int(deltaRounded) // Floor rounding

	r := matrix.SampleMatrix(par.M, 1, new(big.Int).SetInt64(2))

	mu_q := matrix.MultiplyMatrixByConstant(mu, deltaRounded, par.Q)
	s := matrix.MultiplyMatrixByConstant(smu, deltaRounded, par.Q)

	Ar := matrix.MultiplyMatricesParallel(A, r, par.Q)
	CT := matrix.Transpose(C)
	CTs := matrix.MultiplyMatricesParallel(CT, s, par.Q)
	c0 := matrix.AddMatrices(Ar, CTs, par.Q)

	Ur := matrix.MultiplyMatricesParallel(U, r, par.Q)
	DT := matrix.Transpose(D)
	DTs := matrix.MultiplyMatricesParallel(DT, s, par.Q)
	sum := matrix.AddMatrices(Ur, DTs, par.Q)
	c1 := matrix.AddMatrices(sum, mu_q, par.Q)

	return [2]matrix.BigIntMatrix{c0, c1}
}

func ADec(tk matrix.BigIntMatrix, act [2]matrix.BigIntMatrix, apk PublicKey) matrix.BigIntMatrix {
	c0 := act[0]
	par := apk.Params
	k := matrix.Log2BigInt(par.Q)

	splitIndex := par.L*k + 2*lam

	c0_part1 := matrix.SliceBigIntMatrixColRange(c0, 0, splitIndex, 0, 1)
	c0_part2 := matrix.SliceBigIntMatrixColRange(c0, splitIndex, len(c0), 0, 1)

	RT := matrix.Transpose(tk)
	tmp := matrix.MultiplyMatricesParallel(RT, c0_part1, par.Q)
	c0_diff := matrix.SubtractMatricesParallel(c0_part2, tmp, par.Q)

	S := matrix.CalculateSMatrixParallel(k, par.L, par.Q)
	ST := matrix.Transpose(S)
	diff_T := matrix.MultiplyMatricesParallel(ST, c0_diff, par.Q)
	Gs := matrix.SubtractMatricesParallel(c0_diff, diff_T, par.Q)
	s := matrix.RecoverKthColumn(Gs, k, par.L)
	sFinal := matrix.ScaleAndRoundMatrix(s, par.P, par.Q)

	return sFinal
}
