package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

//https://asecuritysite.com/golang/circl_pairing

type Ciphertext struct {
	ct0 *bls.G1
	ct1 *bls.Gt
	ct2 *bls.G2
	ct3 *bls.Gt
}

func Encrypt(pp *PublicParams, recvId int, msg *bls.Gt) *Ciphertext {
	hParamsG1 := pp.crs.hParamsG1
	hParamsG2 := pp.crs.hParamsG2

	pp.CheckIdRange(recvId)

	// block index
	k := pp.IdToBlock(recvId)
	recvBar := pp.IdToIdBar(recvId)

	g2 := pp.g2
	com := pp.Commitments[k]

	r := randomScalar()

	ct0 := com

	ct1 := bls.Pair(com, hParamsG2[pp.blockSize-1-recvBar])
	ct1.Exp(ct1, r)

	ct2 := new(bls.G2)
	ct2.ScalarMult(r, g2)

	ct3 := bls.Pair(hParamsG1[recvBar], hParamsG2[pp.blockSize-1-recvBar])
	ct3.Exp(ct3, r)
	ct3.Mul(ct3, msg)

	return &Ciphertext{ct0, ct1, ct2, ct3}
}
