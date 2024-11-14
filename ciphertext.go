package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type Ciphertext struct {
	ct0 *bls.G1
	ct1 *bls.Gt
	ct2 *bls.G2
	ct3 *bls.Gt
}