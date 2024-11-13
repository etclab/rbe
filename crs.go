package rbe

import (
	"crypto/rand"
	"math"
	"math/big"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
)

//https://asecuritysite.com/golang/circl_pairing

var groupOrder *big.Int

type CRS struct {
	n         int
	blockSize int
	g1        *bls.G1
	g2        *bls.G2
	hParamsG1 []*bls.G1
	hParamsG2 []*bls.G2
}

func init() {
	groupOrder = new(big.Int)
	groupOrder.SetBytes(bls.Order())
}

func randomZ() *big.Int {
	z, err := rand.Int(rand.Reader, groupOrder)
	if err != nil {
		mu.Panicf("randomZ: %v", err)
	}
	return z
}

func modPow(base *big.Int, exp int) *big.Int {
	z := new(big.Int)
	x := big.NewInt(int64(exp))
	z.Exp(base, x, groupOrder)
	return z
}

func bigIntToScalar(x *big.Int) *bls.Scalar {
	s := &bls.Scalar{}
	bytes := x.Bytes()
	s.SetBytes(bytes)
	return s
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

		e1 := &bls.G1{}
		e1.ScalarMult(k, s.g1)
		s.hParamsG1[i] = e1

		e2 := &bls.G2{}
		e2.ScalarMult(k, s.g2)
		s.hParamsG2[i] = e2
	}

	return s
}
