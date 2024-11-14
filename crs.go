package rbe

import (
	"math"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

//https://asecuritysite.com/golang/circl_pairing

type CRS struct {
	n         int
	blockSize int
	g1        *bls.G1
	g2        *bls.G2
	hParamsG1 []*bls.G1
	hParamsG2 []*bls.G2
}

func NewCRS(n int) *CRS {
	s := &CRS{}

	s.n = n
	s.blockSize = int(math.Ceil(math.Sqrt(float64(n))))
	s.g1 = bls.G1Generator()
	s.g2 = bls.G2Generator()

	z := randomZ()
	s.hParamsG1 = make([]*bls.G1, n*2)
	s.hParamsG2 = make([]*bls.G2, n*2)

	for i := 0; i < (2 * n); i++ {
		if i == n {
			continue
		}

		k := bigIntToScalar(modPow(z, i))

		e1 := new(bls.G1)
		e1.ScalarMult(k, s.g1)
		s.hParamsG1[i] = e1

		e2 := new(bls.G2)
		e2.ScalarMult(k, s.g2)
		s.hParamsG2[i] = e2
	}

	return s
}
