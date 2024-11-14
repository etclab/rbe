package rbe

import (
	"crypto/rand"
	"math/big"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
)

var groupOrder *big.Int

func init() {
	groupOrder = new(big.Int)
	groupOrder.SetBytes(bls.Order())
}

func randomScalar() *bls.Scalar {
	z := new(bls.Scalar)
	z.Random(rand.Reader)
	return z
}

// TODO: use randomScalar instead
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
