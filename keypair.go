package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

//https://asecuritysite.com/golang/circl_pairing

type KeyPair struct {
	PublicKey *bls.G1
	SecretKey *bls.Scalar

	// len=blockSize; The paper also calls this "helping information"
	Xi []*bls.G1
}

func NewKeyPair(pp *PublicParams, id int) *KeyPair {
	pp.CheckIdRange(id)

	hParamsG1 := pp.crs.hParamsG1

	sk := randomScalar()
	idBar := pp.IdToIdBar(id)
	h := hParamsG1[idBar]
	pk := new(bls.G1)
	pk.ScalarMult(sk, h)

	xi := make([]*bls.G1, pp.blockSize)
	for j := 0; j < pp.blockSize; j++ {
		i := pp.blockSize - 1 - j
		if hParamsG1[idBar+j+1] == nil {
			continue
		}
		xi[i] = new(bls.G1)
		xi[i].ScalarMult(sk, hParamsG1[idBar+j+1])
	}

	return &KeyPair{
		PublicKey: pk,
		SecretKey: sk,
		Xi:        xi,
	}
}
