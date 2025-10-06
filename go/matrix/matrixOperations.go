package matrix

import (
	"crypto/rand"
	"fmt"
	"log"
	"math"
	"math/big"
	mrand "math/rand"
	"runtime"
	"sync"
	"time"
)

type BigIntMatrix [][]*big.Int

var rng = mrand.New(mrand.NewSource(time.Now().UnixNano()))

// Generates a random matrix of size (rows x cols)
// with entries uniformly sampled from Z_q (integers modulo q).
func SampleMatrix(rows, cols int, q *big.Int) BigIntMatrix {
	// Allocate the outer slice for the matrix with 'rows' number of rows.
	matrix := make(BigIntMatrix, rows)

	// Loop over each row index.
	for i := 0; i < rows; i++ {
		// Allocate a slice for the current row with 'cols' number of columns.
		matrix[i] = make([]*big.Int, cols)

		// Fill each element of the current row.
		for j := 0; j < cols; j++ {
			// Sample uniformly at random in [0, q-1]
			matrix[i][j] = new(big.Int).Rand(rng, q)
		}
	}
	return matrix
}

// Generates a matrix of size (rows x cols) where each entry
// is sampled from a discrete Gaussian (normal) distribution
// with mean 0 and given standard deviation (stddev).
func SampleError(rows, cols int, stddev float64, mod *big.Int) BigIntMatrix {
	// Allocate memory for the current row with 'cols' number of columns.
	matrix := make(BigIntMatrix, rows)

	// Loop through each row.
	for i := 0; i < rows; i++ {
		matrix[i] = make([]*big.Int, cols)
		// Allocate memory for the current row with 'cols' number of columns.

		// Generate Gaussian samples for each element in the row.
		for j := 0; j < cols; j++ {
			// Draw a sample from N(0, stddev^2)
			x := rng.NormFloat64() * stddev

			// Round to nearest integer
			intVal := int64(math.Round(x))

			// Store as big.Int
			matrix[i][j] = new(big.Int).SetInt64(intVal)
		}
	}
	return matrix
}

// SampleMatrixP generates an m × n matrix where
// each entry is from P = {-1:1/4, 0:1/2, +1:1/4}
func SampleMatrixP(m, n int) BigIntMatrix {
	// Allocate the outer slice for the matrix with 'm' rows.
	matrix := make([][]*big.Int, m)

	// Iterate over each row.
	for i := 0; i < m; i++ {
		// Allocate the inner slice for the current row with 'n' columns.
		row := make([]*big.Int, n)

		// Fill teh row with sampled values.
		for j := 0; j < n; j++ {
			// Sample from {0, 1, 2, 3} and map to {-1, 0, 1}
			randVal, err := rand.Int(rand.Reader, big.NewInt(4))
			if err != nil {
				log.Fatalf("crand.Int error: %v", err)
			}

			// Map r to {-1, 0, 1} according to the defined probabilites.
			switch randVal.Int64() {
			case 0, 1:
				row[j] = big.NewInt(0)
			case 2:
				row[j] = big.NewInt(-1)
			case 3:
				row[j] = big.NewInt(1)
			}
		}

		// Store the row in the matrix
		matrix[i] = row
	}
	return matrix
}

// Multiplies two matrices (a * b) with entries in Z_mod.
// using parallelism to speed up computation.
func MultiplyMatricesParallel(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows := len(a)     // number of rows in 'a'
	cols := len(b[0])  // number of columns in 'b'
	inner := len(a[0]) // shared inner dimensions (a.cols == b.rows)

	// Allocate result matrix (rows x cols), initialized with zeros
	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			result[i][j] = new(big.Int) // each entry starts as 0
		}
	}

	// Determine number of workers = number of CPU cores
	numWorkers := runtime.NumCPU()
	runtime.GOMAXPROCS(numWorkers)

	// Split the work into batches of rows per worker
	batchSize := (rows + numWorkers - 1) / numWorkers

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		start := w * batchSize
		end := start + batchSize
		if end > rows {
			end = rows
		}
		if start >= rows {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()

			tmp := new(big.Int) // temporary for multplication
			sum := new(big.Int) // accumulator for each cell

			// Multiply the corresponding row (from 'a') and column (from 'b')
			for i := start; i < end; i++ {
				for j := 0; j < cols; j++ {
					sum.SetInt64(0) // reset accumulator
					for k := 0; k < inner; k++ {
						tmp.Mul(a[i][k], b[k][j]) // a[i][j] * b[k][j]
						sum.Add(sum, tmp)         // accumulate
					}
					result[i][j].Mod(sum, mod) // reduce modulo 'mod'
				}
			}
		}(start, end)
	}

	wg.Wait() // wait for all goroutines to finish
	return result
}

// Returns the transpose of a given matrix.
func Transpose(matrix BigIntMatrix) BigIntMatrix {
	// Handle empty matrix cases to avoid intex out-of-range errors.
	if len(matrix) == 0 || len(matrix[0]) == 0 {
		return nil
	}

	// Determine the number of rows and columns in the input matrix.
	rows := len(matrix)
	cols := len(matrix[0])

	// Create transposed matrix
	transposed := make(BigIntMatrix, cols)
	for i := range transposed {
		transposed[i] = make([]*big.Int, rows)
	}

	// Fill transposed matrix
	for i := 0; i < rows; i++ {
		for j := 0; j < cols; j++ {
			transposed[j][i] = new(big.Int).Set(matrix[i][j])
		}
	}

	return transposed
}

// Multiplies every entry of matrix 'a' by 'constant'
// and reduces the result modulo 'mod'
func MultiplyMatrixByConstant(a BigIntMatrix, constant, mod *big.Int) BigIntMatrix {
	rows, cols := len(a), len(a[0])

	// Allocate result matrix with same dimensions
	result := make(BigIntMatrix, rows)

	// Temporary variable to hold intermediate products
	tmp := new(big.Int)
	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Multiply entry by the constant
			tmp.Mul(a[i][j], constant)

			// Reduce modulo 'mod' and store in result
			result[i][j] = new(big.Int).Mod(tmp, mod)
		}
	}
	return result
}

// Adds two matrices 'a' and 'b' element-wise modulo mod
func AddMatrices(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows, cols := len(a), len(a[0])

	// Allocate result matrix
	result := make(BigIntMatrix, rows)

	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Add entries a[i][j] + b[i][j]
			sum := new(big.Int).Add(a[i][j], b[i][j])

			// Reduce modulo 'mod' and store in result
			result[i][j] = sum.Mod(sum, mod)
		}
	}
	return result
}

// appendRows stacks two matrices vertically:
// A: r1 x c, B: r2 x c → result: (r1+r2) x c
func AppendRows(A, B BigIntMatrix) BigIntMatrix {
	// If A is empty, just return B
	if len(A) == 0 {
		return B
	}
	// If B is empty, just return A
	if len(B) == 0 {
		return A
	}

	// Ensure both matrices have the same number of columns
	colsA := len(A[0])
	colsB := len(B[0])
	if colsA != colsB {
		panic(fmt.Sprintf("appendRows: mismatched column sizes (%d vs %d)", colsA, colsB))
	}

	// Total number of rows in the new matrix = rows of A + rows of B
	rows := len(A) + len(B)
	cols := colsA

	// Allocate result matrix with (rows x cols)
	result := make(BigIntMatrix, rows)

	// Copy rows from A into the result
	for i := 0; i < len(A); i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Copy value (deep copy to avoid aliasing)
			result[i][j] = new(big.Int).Set(A[i][j])
		}
	}
	// Copy rows from B into the result (after rows of A)
	for i := 0; i < len(B); i++ {
		result[len(A)+i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Copy value (deep copy to avoid aliasing)
			result[len(A)+i][j] = new(big.Int).Set(B[i][j])
		}
	}
	return result
}

// Concatenates two matrices horizontally: [A | B]
func HorzConcat(A, B BigIntMatrix, q *big.Int) BigIntMatrix {
	rows := len(A) // number of rows in A

	// If A is empty, just return B
	if rows == 0 {
		return B
	}

	colsA := len(A[0]) // number of columns in A
	colsB := len(B[0]) // number of columns in B

	// Allocate result matrix with rows x (colsA + cols B)
	res := make(BigIntMatrix, rows)

	for i := 0; i < rows; i++ {
		res[i] = make([]*big.Int, colsA+colsB) // allocate each row

		// Copy entries from A into the first colsA columns
		for j := 0; j < colsA; j++ {
			res[i][j] = new(big.Int).Mod(new(big.Int).Set(A[i][j]), q)
		}

		// Copy entries from B into the next colsB columns
		for j := 0; j < colsB; j++ {
			res[i][colsA+j] = new(big.Int).Mod(new(big.Int).Set(B[i][j]), q)
		}
	}

	return res
}

// Checks if two matrices are equal.
// Returns true if dimensions and all entries match.
func CompareMatrices(a, b BigIntMatrix) bool {
	// Check if number of rows matches
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		// Check if number of columns mathes for each row
		if len(a[i]) != len(b[i]) {
			return false
		}

		for j := range a[i] {
			// Compare corresponding entries using big.Int.Cmp
			// Cmp returs 0 if the two big.Int values are equal
			if a[i][j].Cmp(b[i][j]) != 0 {
				return false
			}
		}
	}

	// All checks passed -> matrices are equal
	return true
}

// Constructs the gadget matrix G in parallel
func GadgetMatrixParallel(n, k int, q *big.Int) BigIntMatrix {
	// Build the base gadget vector g = (1, 2, 4, ..., 2*(k-1))
	g := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		val := new(big.Int).Lsh(big.NewInt(1), uint(i))
		val.Mod(val, q)
		g[i] = val
	}

	// Initialize empty matrix G with dimensions n x (n*k)
	rows := n
	cols := n * k
	G := make(BigIntMatrix, rows)
	for i := range G {
		G[i] = make([]*big.Int, cols)
		for j := range G[i] {
			G[i][j] = big.NewInt(0)
		}
	}

	// Parallelization settings
	numWorkers := 8 // fixed number of goroutines
	batchSize := (rows + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup

	// Split rows into chunks and assign to workers
	for w := 0; w < numWorkers; w++ {
		start := w * batchSize
		end := start + batchSize
		if end > rows {
			end = rows
		}
		if start >= rows {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			for i := start; i < end; i++ {
				base := i * k // start index for row i
				for j := 0; j < k; j++ {
					// Place g[j] in the correct block position
					G[i][base+j] = new(big.Int).Set(g[j])
				}
			}
		}(start, end)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	return G
}

// Computer the gadget inverse (or base decomposition) of a vector over Zq.
func GadgetInverse(vec []*big.Int, q *big.Int, base int64) BigIntMatrix {

	// Compute k = ceil(log_base(q))
	// using float (if q is small enough to convert safely)
	qf, _ := new(big.Float).SetInt(q).Float64()
	k := int(math.Ceil(math.Log(qf) / math.Log(float64(base))))

	// Prepare a slice to hold all decomposed digits.
	digits := make([]*big.Int, 0, len(vec)*k)

	baseBig := big.NewInt(base)

	// Decompose each element of vec into base-'base' digits
	for _, x := range vec {
		y := new(big.Int).Set(x) // make a copy so we don't modify input

		for i := 0; i < k; i++ {
			// Compute least significant digit: y mod base
			digit := new(big.Int).Mod(y, baseBig)

			// Append the digit to the digit list
			digits = append(digits, digit)

			// Integer division: y = y / base
			y.Div(y, baseBig)
		}
	}

	// Convert the digit list into a column matrix
	res := make(BigIntMatrix, len(digits))
	for i := range digits {
		// Each row contains a single digit as a 1-column matrix
		res[i] = []*big.Int{digits[i]}
	}

	return res
}

// RoundDiv returns ⌊a/b⌉ (round to nearest integer).
func RoundDiv(a, b *big.Int) *big.Int {
	// Compute integer division with remainder: a = b*q + r
	q, r := new(big.Int), new(big.Int)
	q.QuoRem(a, b, r) // q = a/b (truncated), r = remainder

	// Compute half of the divisor (b/2) for rounding comparison
	half := new(big.Int).Div(b, big.NewInt(2))

	// If remainder ≥ b/2, increment q to round up
	if r.Cmp(half) >= 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

// Computers (A-B) mod q int parallel, where A
// and B are matrices of the same dimensions.
func SubtractMatricesParallel(a, b BigIntMatrix, mod *big.Int) BigIntMatrix {
	rows := len(a)
	cols := len(a[0])

	// Allocate memory for the result matrix
	result := make(BigIntMatrix, rows)
	for i := range result {
		result[i] = make([]*big.Int, cols)
		for j := range result[i] {
			result[i][j] = new(big.Int)
		}
	}

	// COnfigure parallelization
	numWorkers := 8 // number of concurrent goroutines
	batchSize := (rows + numWorkers - 1) / numWorkers
	var wg sync.WaitGroup

	// Process each chunk of rows in parallel
	for w := 0; w < numWorkers; w++ {
		start := w * batchSize
		end := start + batchSize
		if end > rows {
			end = rows
		}
		if start >= rows {
			break
		}

		wg.Add(1)
		go func(start, end int) {
			defer wg.Done()
			diff := new(big.Int)

			// Iterate through assigned rows and compute (a-b) mod q
			for i := start; i < end; i++ {
				for j := 0; j < cols; j++ {
					// diff = a[i][j] - b[i][j]
					diff.Sub(a[i][j], b[i][j])

					// Reduce modulo q (ensure non-negative result)
					result[i][j].Mod(diff, mod)
					if result[i][j].Sign() < 0 {
						result[i][j].Add(result[i][j], mod)
					}
				}
			}
		}(start, end)
	}

	// Wait for all worker goroutines to finish
	wg.Wait()
	return result
}

// Returns ⌈log₂(x)⌉ for a positive big integer x.
func Log2BigInt(x *big.Int) int {
	// Get the bit length of x.
	bitLen := x.BitLen()

	// Check if x is a power of 2
	if new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitLen-1)), nil).Cmp(x) == 0 {
		return bitLen - 1
	}
	return bitLen
}

// Constructs the block matrix S = Iₙ ⊗ Sₖ (Kronecker product) in parallel
func CalculateSMatrixParallel(k, n int, q *big.Int) BigIntMatrix {
	// Create qBits vector of k least significant bits of q
	qBits := make([]*big.Int, k)
	for i := 0; i < k; i++ {
		bit := q.Bit(i)
		qBits[i] = big.NewInt(int64(bit))
	}

	// Construct Sk matrix (k x k)
	Sk := make(BigIntMatrix, k)
	for i := 0; i < k; i++ {
		Sk[i] = make([]*big.Int, k)
		for j := 0; j < k; j++ {
			Sk[i][j] = big.NewInt(0)
		}
	}
	for i := 0; i < k; i++ {
		if i > 0 {
			Sk[i][i-1] = big.NewInt(-1) // Subdiagonal
		}
		if i < k-1 {
			Sk[i][i] = big.NewInt(2) // Main diagonal
		}
		Sk[i][k-1] = new(big.Int).Set(qBits[i]) // Last column from qBits
	}

	// Initialize output S of size (n*k) x (n*k)
	rows := n * k
	cols := n * k
	S := make(BigIntMatrix, rows)
	for i := 0; i < rows; i++ {
		S[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			S[i][j] = big.NewInt(0)
		}
	}

	// Parallelize the Kronecker product
	numWorkers := 8
	type task struct{ i, j int }

	tasks := make(chan task, n*n)
	var wg sync.WaitGroup

	// Worker goroutines copy Sₖ into the correct diagonal block position.
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasks {
				if t.i == t.j { // since I is identity
					for r := 0; r < k; r++ {
						for c := 0; c < k; c++ {
							val := new(big.Int).Set(Sk[r][c]) // copy Sk element
							S[t.i*k+r][t.j*k+c] = val
						}
					}
				}
			}
		}()
	}

	// Enqueue diagonal tasks (only where Iₙ has 1s)
	for i := 0; i < n; i++ {
		tasks <- task{i, i} // Only the diagonal (since I is identity)
	}
	close(tasks)

	// Wait for all goroutines to finish
	wg.Wait()

	return S
}

// Returns a submatrix of the input matrix.
func SliceBigIntMatrixColRange(matrix BigIntMatrix, rowStart, rowEnd, colStart, colEnd int) BigIntMatrix {
	// Validate row and column ranges
	if rowStart < 0 || rowEnd > len(matrix) || rowStart > rowEnd {
		panic("invalid row range")
	}
	if len(matrix) == 0 || colStart < 0 || colEnd > len(matrix[0]) || colStart > colEnd {
		panic("invalid column range")
	}

	// Allocate the new submatrix
	sliced := make(BigIntMatrix, rowEnd-rowStart)

	// Copy elements (deep copy) from the original matrix
	for i := rowStart; i < rowEnd; i++ {
		row := make([]*big.Int, colEnd-colStart)
		for j := colStart; j < colEnd; j++ {
			// Deep copy: create a new *big.Int for each element
			row[j-colStart] = new(big.Int).Set(matrix[i][j])
		}
		sliced[i-rowStart] = row
	}
	return sliced
}

// Extracts the k-th "block column" from a block-structured matrix
// Gs and returns it as an n x 1 column vector
func RecoverKthColumn(Gs BigIntMatrix, k int, n int) BigIntMatrix {
	// Allocate output column vector
	s := make(BigIntMatrix, n)

	// Iterate over each block to extract the element in the k-th column
	for i := 0; i < n; i++ {
		// Deep copy the element from row i*k, column 0
		s[i] = []*big.Int{new(big.Int).Set(Gs[i*k][0])}
	}
	return s
}

// Scales each element of a matrix by p/q and rounds to
// the nearest integer modulo p.
func ScaleAndRoundMatrix(a BigIntMatrix, p, q *big.Int) BigIntMatrix {
	rows := len(a)
	cols := len(a[0])

	// Allocate output matrix
	result := make(BigIntMatrix, rows)

	// Convert p and q to big.Float for accurate division
	pf := new(big.Float).SetInt(p)
	qf := new(big.Float).SetInt(q)

	// Iterate over all elements
	for i := 0; i < rows; i++ {
		result[i] = make([]*big.Int, cols)
		for j := 0; j < cols; j++ {
			// Covert element to float
			val := new(big.Float).SetInt(a[i][j])

			// Scale: val * p/q
			scaled := new(big.Float).Quo(new(big.Float).Mul(val, pf), qf)

			// Round to nearest integer: add 0.5 before truncation
			rounded := new(big.Float).Add(scaled, big.NewFloat(0.5))

			// Convert back to big.Int
			intVal := new(big.Int)
			rounded.Int(intVal)

			// Reduce modulo p, ensuring non-negative result
			intVal.Mod(intVal, p)
			if intVal.Sign() < 0 {
				intVal.Add(intVal, p)
			}
			result[i][j] = intVal
		}
	}
	return result
}
