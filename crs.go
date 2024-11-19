package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type CRS struct {
	// h[i] = g1**{z**i}, where i ranges form 1 to 2n, inclusive
	hParamsG1 []*bls.G1 // h_parameters_g1
	// h[i] = g2**{z**i}, where i ranges form 1 to 2n, inclusive
	hParamsG2 []*bls.G2 // h_parameters_g2
}

func NewCRS(g1 *bls.G1, g2 *bls.G2, blockSize int) *CRS {
	crs := new(CRS)

	crs.hParamsG1 = make([]*bls.G1, blockSize*2)
	crs.hParamsG2 = make([]*bls.G2, blockSize*2)

	z := randomZ()

	for i := 0; i < (2 * blockSize); i++ {
		if i == blockSize {
			continue
		}

		k := bigIntToScalar(modPow(z, i))

		e1 := new(bls.G1)
		e1.ScalarMult(k, g1)
		crs.hParamsG1[i] = e1

		e2 := new(bls.G2)
		e2.ScalarMult(k, g2)
		crs.hParamsG2[i] = e2
	}

	return crs
}
