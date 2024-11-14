package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

// Public Parameters
type PublicParams struct {
	// indexed by the block numbers
	commitments []*bls.G1
}

func NewPublicParams(numBlocks int) *PublicParams {
	pp := new(PublicParams)

	pp.commitments = make([]*bls.G1, numBlocks)
	for i := 0; i < numBlocks; i++ {
		pp.commitments[i].SetIdentity()
	}

	return pp
}
