package rbe

import (
	"math"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

//https://asecuritysite.com/golang/circl_pairing

// Public Parameters and CRS
type PublicParams struct {
	maxUsers  int // N
	blockSize int // n
	numBlocks int // B

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
	pp.numBlocks = int(math.Ceil(float64(pp.maxUsers) / float64(pp.blockSize)))

	pp.g1 = bls.G1Generator()
	pp.g2 = bls.G2Generator()

	z := randomZ()
	pp.hParamsG1 = make([]*bls.G1, pp.blockSize*2)
	pp.hParamsG2 = make([]*bls.G2, pp.blockSize*2)

	for i := 0; i < (2 * pp.blockSize); i++ {
		if i == pp.blockSize {
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

type KeyPair struct {
	PublicKey *bls.G1
	SecretKey *bls.Scalar
	Xi        []*bls.G1
}

func NewKeyPair(pp *PublicParams, id int) (*KeyPair, error) {
	if id < 0 || id >= pp.maxUsers {
		return nil, ErrInvalidId
	}

	idIndex := id % pp.blockSize
	sk := randomScalar()
	h := pp.hParamsG1[idIndex]
	pk := new(bls.G1)
	pk.ScalarMult(sk, h)

	xi := make([]*bls.G1, pp.blockSize)
	for j := 0; j < pp.blockSize; j++ {
		i := pp.blockSize - 1 - j
		if pp.hParamsG1[idIndex+j+1] == nil {
			continue
		}
		xi[i].ScalarMult(sk, pp.hParamsG1[idIndex+j+1])
	}

	return &KeyPair{
		PublicKey: pk,
		SecretKey: sk,
		Xi:        xi,
	}, nil
}

type Ciphertext struct {
	ct0 *bls.G1
	ct1 *bls.Gt
	ct2 *bls.G2
	ct3 *bls.Gt
}
