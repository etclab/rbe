package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type KeyPair struct {
	PublicKey *bls.G1
	SecretKey *bls.Scalar

	// len=blockSize; The paper also calls this "helping information"
	Xi []*bls.G1
}

func NewKeyPair(pp *PublicParams, id int, secretKey *bls.Scalar) *KeyPair {
	pp.CheckIdRange(id)

	h1 := pp.CRS.H1

	sk := secretKey
	if sk == nil {
		sk = RandomScalar()
	}

	idBar := pp.IdToIdBar(id)
	h := h1[idBar]
	pk := new(bls.G1)
	pk.ScalarMult(sk, h)

	xi := make([]*bls.G1, pp.BlockSize)
	for j := 0; j < pp.BlockSize; j++ {
		i := pp.BlockSize - 1 - j
		if h1[idBar+j+1] == nil {
			continue
		}
		xi[i] = new(bls.G1)
		xi[i].ScalarMult(sk, h1[idBar+j+1])
	}

	return &KeyPair{
		PublicKey: pk,
		SecretKey: sk,
		Xi:        xi,
	}
}
