package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
)

// n is the maximum number of users.
func Setup(n int) *CRS {
	// TODO:should also return pp and aux
	crs := NewCRS(n)
	return crs
}

func GenerateKeyPair(crs *CRS, id int) (*bls.G1, *bls.Scalar, []*bls.G1) {
	idIndex := id % crs.n
	sk := randomScalar()
	h := crs.hParamsG1[idIndex]
	pk := new(bls.G1)
	pk.ScalarMult(sk, h)

	xi := make([]*bls.G1, crs.n)
	for j := 0; j < crs.n; j++ {
		i := crs.n - 1 - j
		if crs.hParamsG1[idIndex+j+1] == nil {
			continue
		}
		xi[i].ScalarMult(sk, crs.hParamsG1[idIndex+j+1])
	}

	return pk, sk, xi

}

func Register(crs *CRS, pp *PublicParams, id int, pk *bls.G1, xi []*bls.G1) {
	// block index
	k := id / crs.blockSize
	idIndex := id % crs.blockSize

	// TODO: make this a separate function
	// check consistency of the helping values (xi)
	hParams := crs.hParamsG2
	e := bls.Pair(pk, hParams[crs.n-1])
	for i := 0; i < (crs.n - 1); i++ {
		if xi[i+1] == nil {
			continue
		}
		if hParams[i] == nil {
			continue
		}

		tmp := bls.Pair(xi[i+1], hParams[i])
		if !e.IsEqual(tmp) {
			mu.Fatalf("helping values (xi) are not consistent!")
		}
	}

	// fetch and update commitment
	com := pp.commitments[k]
	com.Add(com, pk)

	mu.UNUSED(k)
	mu.UNUSED(idIndex)
}

func Encrypt(crs *CRS, id int, m *bls.G1) *Ciphertext {
	mu.UNUSED(crs)
	mu.UNUSED(id)
	mu.UNUSED(m)
	return nil
}

func Update(crs *CRS, id int) []*bls.G1 {
	mu.UNUSED(crs)
	mu.UNUSED(id)
	return nil

}

func Decrypt(crs *CRS, id int, sk *bls.Scalar, updates []*bls.G1, ct *Ciphertext, updateIndex int) *bls.Gt {
	mu.UNUSED(crs)
	mu.UNUSED(id)
	mu.UNUSED(sk)
	mu.UNUSED(updates)
	mu.UNUSED(ct)
	mu.UNUSED(updateIndex)
	return nil
}
