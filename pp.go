package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

// Public Parameters
type PublicParams struct {
	// indexed by the block number
	commitments []*bls.G1

	// indexed by the block number; stores the number of parties registered in
	// each block
	auxCount []int
	aux      []*bls.G1 // TODO: what is the size of this array
}

func NewPublicParams(numBlocks int) *PublicParams {
	pp := new(PublicParams)

	pp.commitments = make([]*bls.G1, numBlocks)
	for i := 0; i < numBlocks; i++ {
		pp.commitments[i].SetIdentity()
	}

	pp.auxCount = make([]int, numBlocks)

	/* TODO: I'm not sure the size of this array
	pp.aux = make([]*bls.G1, ???)
	for i := 0; i < ???; i++ {
		pp.aux[i].SetIdentity()
	}
	*/

	return pp
}
