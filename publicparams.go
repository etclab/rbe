package rbe

import (
	"fmt"
	"math"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
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
func (pp *PublicParams) CheckXiConsistency(pk *bls.G1, xi []*bls.G1) {
	h2 := pp.CRS.H2
	e := bls.Pair(pk, h2[pp.BlockSize-1])
	for i := 0; i < (pp.BlockSize - 1); i++ {
		if xi[i+1] == nil {
			continue
		}
		if h2[i] == nil {
			continue
		}

		tmp := bls.Pair(xi[i+1], h2[i])
		if !e.IsEqual(tmp) {
			mu.Fatalf("helping values (xi) are not consistent!")
		}
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
