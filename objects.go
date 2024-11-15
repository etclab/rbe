package rbe

import (
	"math"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

//https://asecuritysite.com/golang/circl_pairing

// Public Parameters and CRS
type PublicParams struct {
	maxUsers  int
	blockSize int
	numBlocks int

	g1 *bls.G1
	g2 *bls.G2

	// common reference string
	hParamsG1 []*bls.G1
	hParamsG2 []*bls.G2

	// indexed by the block number
	commitments []*bls.G1

	// indexed by the block number; stores the number of parties registered in
	// each block
	auxCount []int
	aux      []*bls.G1 // TODO: what is the size of this array
}

func NewPublicParams(maxUsers int) *PublicParams {
	pp := new(PublicParams)

	pp.maxUsers = maxUsers
	pp.blockSize = int(math.Ceil(math.Sqrt(float64(maxUsers))))
	pp.numBlocks = pp.maxUsers / pp.blockSize

	pp.g1 = bls.G1Generator()
	pp.g2 = bls.G2Generator()

	z := randomZ()
	pp.hParamsG1 = make([]*bls.G1, maxUsers*2)
	pp.hParamsG2 = make([]*bls.G2, maxUsers*2)

	for i := 0; i < (2 * maxUsers); i++ {
		if i == maxUsers {
			continue
		}

		k := bigIntToScalar(modPow(z, i))

		e1 := new(bls.G1)
		e1.ScalarMult(k, pp.g1)
		pp.hParamsG1[i] = e1

		e2 := new(bls.G2)
		e2.ScalarMult(k, pp.g2)
		pp.hParamsG2[i] = e2
	}

	pp.commitments = make([]*bls.G1, pp.numBlocks)
	for i := 0; i < pp.numBlocks; i++ {
		pp.commitments[i] = new(bls.G1)
		pp.commitments[i].SetIdentity()
	}

	pp.auxCount = make([]int, pp.numBlocks)

	/* TODO: I'm not sure the size of this array
	pp.aux = make([]*bls.G1, ???)
	for i := 0; i < ???; i++ {
		pp.aux[i].SetIdentity()
	}
	*/

	return pp
}

type Ciphertext struct {
	ct0 *bls.G1
	ct1 *bls.Gt
	ct2 *bls.G2
	ct3 *bls.Gt
}
