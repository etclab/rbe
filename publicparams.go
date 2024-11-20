package rbe

import (
	"fmt"
	"math"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/rbe/proto"
)

// Public Parameters and CRS
type PublicParams struct {
	// Public Params
	maxUsers  int // N
	blockSize int // n
	numBlocks int // B

	g1 *bls.G1
	g2 *bls.G2

	crs *CRS

	// Commitment C for each block ; indexed by the block number
	Commitments []*bls.G1 // in the paper, these are just called `pp`
}

func (pp *PublicParams) FromProto(protoPp *proto.PublicParams) {
	pp.maxUsers = int(protoPp.GetMaxUsers())
	pp.blockSize = int(protoPp.GetBlockSize())
	pp.numBlocks = int(protoPp.GetNumBlocks())

	pp.g1 = new(bls.G1)
	pp.g1.SetBytes(protoPp.GetG1().GetBytes())

	pp.g2 = new(bls.G2)
	pp.g2.SetBytes(protoPp.GetG2().GetBytes())

	pp.crs = new(CRS)
	pp.crs.FromProto(protoPp.GetCrs())

	pp.Commitments = make([]*bls.G1, pp.numBlocks)
	for i, v := range protoPp.GetCommitments() {
		pp.Commitments[i] = new(bls.G1)
		pp.Commitments[i].SetBytes(v.GetBytes())
	}
}

func (pp *PublicParams) ToProto() *proto.PublicParams {
	commitments := []*proto.G1{}
	for _, v := range pp.Commitments {
		commitG1 := &proto.G1{Bytes: v.Bytes()}
		commitments = append(commitments, commitG1)
	}

	return &proto.PublicParams{
		MaxUsers:    int32(pp.maxUsers),
		BlockSize:   int32(pp.blockSize),
		NumBlocks:   int32(pp.numBlocks),
		G1:          &proto.G1{Bytes: pp.g1.Bytes()},
		G2:          &proto.G2{Bytes: pp.g2.Bytes()},
		Crs:         pp.crs.ToProto(),
		Commitments: commitments,
	}
}

func NewPublicParams(maxUsers int) *PublicParams {
	pp := new(PublicParams)

	pp.maxUsers = maxUsers
	pp.blockSize = int(math.Ceil(math.Sqrt(float64(maxUsers))))
	pp.numBlocks = int(math.Ceil(float64(pp.maxUsers) / float64(pp.blockSize)))

	pp.g1 = bls.G1Generator()
	pp.g2 = bls.G2Generator()

	pp.crs = NewCRS(pp.g1, pp.g2, pp.blockSize)

	pp.Commitments = make([]*bls.G1, pp.numBlocks)
	for i := 0; i < pp.numBlocks; i++ {
		pp.Commitments[i] = new(bls.G1)
		pp.Commitments[i].SetIdentity()
	}

	return pp
}

func (pp *PublicParams) String() string {
	sb := new(strings.Builder)

	sb.WriteString("PublicParams: {")
	fmt.Fprintf(sb, "\tmaxUsers: %d,\n", pp.maxUsers)
	fmt.Fprintf(sb, "\tblockSize: %d,\n", pp.blockSize)
	fmt.Fprintf(sb, "\tnumBlocks: %d,\n", pp.numBlocks)
	fmt.Fprintf(sb, "\tg1: %v,\n", pp.g1)
	fmt.Fprintf(sb, "\tg2: %v,\n", pp.g2)
	fmt.Fprintf(sb, "\t%v\n}", pp.crs)

	return sb.String()
}

func (pp *PublicParams) GetGenerators() (*bls.G1, *bls.G2) {
	return pp.g1, pp.g2
}

// check consistency of the helping values (xi)
func (pp *PublicParams) CheckXiConsistency(pk *bls.G1, xi []*bls.G1) {
	hParams := pp.crs.hParamsG2
	e := bls.Pair(pk, hParams[pp.blockSize-1])
	for i := 0; i < (pp.blockSize - 1); i++ {
		if xi[i+1] == nil {
			continue
		}
		if hParams[i] == nil {
			continue
		}

		tmp := bls.Pair(xi[i+1], hParams[i])
		if !e.IsEqual(tmp) {
			mu.Fatalf("helping values (xi) are not consistent!")
		}
	}
}

func (pp *PublicParams) CheckIdRange(id int) {
	if id < 0 || id >= pp.maxUsers {
		mu.Fatalf("invalid id %d; id must be in the range [0, %d]", id, pp.maxUsers-1)
	}
}

func (pp PublicParams) IdToBlock(id int) int {
	pp.CheckIdRange(id)
	return id / pp.blockSize
}

func (pp *PublicParams) IdToIdBar(id int) int {
	pp.CheckIdRange(id)
	return id % pp.blockSize
}

// k is the block index
func (pp *PublicParams) IdBarToId(idBar, k int) int {
	id := (k * pp.blockSize) + idBar
	pp.CheckIdRange(id)
	return id
}
