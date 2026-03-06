package rbe

import (
	"crypto/rand"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/rbe/proto"
)

// Public Parameters and CRS
type PublicParams struct {
	// Public Params
	MaxUsers  int // N
	BlockSize int // n
	NumBlocks int // B

	G1 *bls.G1
	G2 *bls.G2

	CRS *CRS

	// Commitment C for each block ; indexed by the block number
	Commitments []*bls.G1 // in the paper, these are just called `pp`
}

func (pp *PublicParams) FromProto(protoPp *proto.PublicParams) {
	pp.MaxUsers = int(protoPp.GetMaxUsers())
	pp.BlockSize = int(protoPp.GetBlockSize())
	pp.NumBlocks = int(protoPp.GetNumBlocks())

	pp.G1 = new(bls.G1)
	err := pp.G1.SetBytes(protoPp.GetG1().GetPoint())
	if err != nil {
		mu.Fatalf("error setting g1: %v", err)
	}

	pp.G2 = new(bls.G2)
	err = pp.G2.SetBytes(protoPp.GetG2().GetPoint())
	if err != nil {
		mu.Fatalf("error setting g2: %v", err)
	}

	pp.CRS = new(CRS)
	pp.CRS.FromProto(protoPp.GetCrs())

	pp.Commitments = make([]*bls.G1, pp.NumBlocks)
	for i, v := range protoPp.GetCommitments() {
		pp.Commitments[i] = new(bls.G1)
		err = pp.Commitments[i].SetBytes(v.GetPoint())
		if err != nil {
			mu.Fatalf("error setting pp.Commitments[%d]: %v", i, err)
		}
	}
}

func (pp *PublicParams) ToProto() *proto.PublicParams {
	commitments := []*proto.G1{}
	for _, v := range pp.Commitments {
		// *bls.G1.Bytes() converts to affine coordinates (x,y,z) -> (x/z,y/z,1)
		// during encoding; meaning the raw bytes when parsed back will not match the
		// original projective coordinates (x,y,z)
		commitG1 := &proto.G1{Point: v.BytesCompressed()}
		commitments = append(commitments, commitG1)
	}

	return &proto.PublicParams{
		MaxUsers:    int64(pp.MaxUsers),
		BlockSize:   int64(pp.BlockSize),
		NumBlocks:   int64(pp.NumBlocks),
		G1:          &proto.G1{Point: pp.G1.BytesCompressed()},
		G2:          &proto.G2{Point: pp.G2.BytesCompressed()},
		Crs:         pp.CRS.ToProto(),
		Commitments: commitments,
	}
}

func NewPublicParams(maxUsers int) *PublicParams {
	pp := new(PublicParams)

	pp.MaxUsers = maxUsers
	pp.BlockSize = int(math.Ceil(math.Sqrt(float64(pp.MaxUsers))))
	pp.NumBlocks = int(math.Ceil(float64(pp.MaxUsers) / float64(pp.BlockSize)))

	pp.G1 = bls.G1Generator()
	pp.G2 = bls.G2Generator()

	pp.CRS = NewCRS(pp.G1, pp.G2, pp.BlockSize)

	pp.Commitments = make([]*bls.G1, pp.NumBlocks)
	for i := 0; i < pp.NumBlocks; i++ {
		pp.Commitments[i] = new(bls.G1)
		pp.Commitments[i].SetIdentity()
	}

	return pp
}

func (pp *PublicParams) String() string {
	sb := new(strings.Builder)

	sb.WriteString("PublicParams: {")
	fmt.Fprintf(sb, "\tMaxUsers: %d,\n", pp.MaxUsers)
	fmt.Fprintf(sb, "\tBlockSize: %d,\n", pp.BlockSize)
	fmt.Fprintf(sb, "\tNumBlocks: %d,\n", pp.NumBlocks)
	fmt.Fprintf(sb, "\tg1: %v,\n", pp.G1)
	fmt.Fprintf(sb, "\tg2: %v,\n", pp.G2)
	fmt.Fprintf(sb, "\t%v\n}", pp.CRS)

	return sb.String()
}

func (pp *PublicParams) GetGenerators() (*bls.G1, *bls.G2) {
	return pp.G1, pp.G2
}

// check consistency of the helping values (xi)
//
// For each valid i, we check e(pk, h2[n-1]) == e(xi[i+1], h2[i]).
// Rearranging: e(pk, h2[n-1]) * e(xi[i+1], h2[i])^{-1} == 1 (in Gt).
//
// We batch all checks with random coefficients r_i, applying them on the
// G1 side (cheaper than G2 scalar mults on BLS12-381):
//
//	e((Σ r_i)*pk, h2[n-1]) * ∏_i e(r_i*xi[i+1], h2[i])^{-1} == 1
//
// With BlockSize=256, entries are split across N goroutines (N = GOMAXPROCS,
// capped at 8). Each goroutine computes scalar mults + ProdPairFrac for its
// chunk; the Gt results are multiplied together and checked for identity.
func (pp *PublicParams) CheckXiConsistency(pk *bls.G1, xi []*bls.G1) {
	h2 := pp.CRS.H2
	n := pp.BlockSize

	// Collect valid indices.
	type entry struct {
		xiIdx int // index into xi (i+1)
		h2Idx int // index into h2 (i)
	}
	var entries []entry
	for i := 0; i < (n - 1); i++ {
		if xi[i+1] == nil || h2[i] == nil {
			continue
		}
		entries = append(entries, entry{i + 1, i})
	}

	if len(entries) == 0 {
		return
	}

	// Generate random scalars and compute their sum.
	scalars := make([]bls.Scalar, len(entries))
	var sumR bls.Scalar
	for j := range scalars {
		if err := scalars[j].Random(rand.Reader); err != nil {
			mu.Fatalf("failed to generate random scalar: %v", err)
		}
		if j == 0 {
			sumR.Set(&scalars[0])
		} else {
			sumR.Add(&sumR, &scalars[j])
		}
	}

	// Build pairing inputs and compute in parallel chunks.
	sumR_pk := new(bls.G1)
	sumR_pk.ScalarMult(&sumR, pk)

	numWorkers := runtime.GOMAXPROCS(0)
	if numWorkers > 8 {
		numWorkers = 8
	}
	if numWorkers > len(entries) {
		numWorkers = len(entries)
	}

	chunkSize := (len(entries) + numWorkers - 1) / numWorkers
	results := make([]*bls.Gt, numWorkers)
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		start := w * chunkSize
		end := start + chunkSize
		if end > len(entries) {
			end = len(entries)
		}
		if start >= end {
			break
		}

		wg.Add(1)
		go func(w, start, end int) {
			defer wg.Done()

			extra := 0
			if w == 0 {
				extra = 1 // pk term in first chunk
			}

			sz := (end - start) + extra
			lg1 := make([]*bls.G1, sz)
			lg2 := make([]*bls.G2, sz)
			lsigns := make([]int, sz)

			if w == 0 {
				lg1[0] = sumR_pk
				lg2[0] = h2[n-1]
				lsigns[0] = 1
			}

			for j := start; j < end; j++ {
				rxi := new(bls.G1)
				rxi.ScalarMult(&scalars[j], xi[entries[j].xiIdx])
				idx := (j - start) + extra
				lg1[idx] = rxi
				lg2[idx] = h2[entries[j].h2Idx]
				lsigns[idx] = -1
			}

			results[w] = bls.ProdPairFrac(lg1, lg2, lsigns)
		}(w, start, end)
	}

	wg.Wait()

	product := new(bls.Gt)
	product.SetIdentity()
	for _, r := range results {
		if r != nil {
			product.Mul(product, r)
		}
	}
	if !product.IsIdentity() {
		mu.Fatalf("helping values (xi) are not consistent!")
	}
}

func (pp *PublicParams) CheckIdRange(id int) {
	if id < 0 || id >= pp.MaxUsers {
		mu.Fatalf("invalid id %d; id must be in the range [0, %d]", id, pp.MaxUsers-1)
	}
}

func (pp PublicParams) IdToBlock(id int) int {
	pp.CheckIdRange(id)
	return id / pp.BlockSize
}

func (pp *PublicParams) IdToIdBar(id int) int {
	pp.CheckIdRange(id)
	return id % pp.BlockSize
}

// k is the block index
func (pp *PublicParams) IdBarToId(idBar, k int) int {
	id := (k * pp.BlockSize) + idBar
	pp.CheckIdRange(id)
	return id
}
