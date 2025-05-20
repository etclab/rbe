package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

func VerifyMembership(pp *PublicParams, id int, pk *bls.G1, proof *bls.G1) bool {
	k := pp.IdToBlock(id)
	comm := pp.Commitments[k]
	idBar := pp.IdToIdBar(id)
	h2 := pp.CRS.H2

	lhs := bls.Pair(comm, h2[pp.BlockSize-1-idBar])
	x := bls.Pair(proof, pp.G2)
	y := bls.Pair(pk, h2[pp.BlockSize-1-idBar])
	rhs := new(bls.Gt)
	rhs.Mul(x, y)

	return lhs.IsEqual(rhs)
}

func VerifyNonMembership(pp *PublicParams, id int, proof *bls.G1) bool {
	k := pp.IdToBlock(id)
	comm := pp.Commitments[k]
	idBar := pp.IdToIdBar(id)
	h2 := pp.CRS.H2

	lhs := bls.Pair(comm, h2[pp.BlockSize-1-idBar])
	rhs := bls.Pair(proof, pp.G2)

	return lhs.IsEqual(rhs)
}
