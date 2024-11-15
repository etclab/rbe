package rbe

import (
	"math"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
)

func Setup(maxUsers int) *PublicParams {
	return NewPublicParams(maxUsers)
}

func GenerateKeyPair(pp *PublicParams, id int) (*bls.G1, *bls.Scalar, []*bls.G1) {
	idIndex := id % pp.blockSize
	sk := randomScalar()
	h := pp.hParamsG1[idIndex]
	pk := new(bls.G1)
	pk.ScalarMult(sk, h)

	xi := make([]*bls.G1, pp.blockSize)
	for j := 0; j < pp.blockSize; j++ {
		i := pp.blockSize - 1 - j
		if pp.hParamsG1[idIndex+j+1] == nil {
			continue
		}
		xi[i].ScalarMult(sk, pp.hParamsG1[idIndex+j+1])
	}

	return pk, sk, xi
}

func Register(pp *PublicParams, id int, pk *bls.G1, xi []*bls.G1) {
	// block index
	k := id / pp.blockSize
	idIndex := id % pp.blockSize
	mu.UNUSED(idIndex)

	// TODO: make this a separate function
	// check consistency of the helping values (xi)
	hParams := pp.hParamsG2
	e := bls.Pair(pk, hParams[pp.blockSize-1])
	for i := 0; i < (pp.blockSize - 1); i++ {
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

	// get the total number of registered parties in the kth block
	numUpd := pp.auxCount[k]

	for i := 0; i < pp.blockSize; i++ {
		// index of first update for id i in block k
		j := k*int(math.Pow(float64(pp.blockSize), 2)) + (i * pp.blockSize)
		if id == ((k * pp.blockSize) + i) {
			// don't update the registering id's aux info
			continue
		}

		lastUpdate := pp.aux[j+numUpd-1]
		newAuxIndex := j + numUpd
		newAuxValue := new(bls.G1)
		newAuxValue.Add(lastUpdate, xi[i])

		pp.aux[newAuxIndex] = newAuxValue
		pp.auxCount[k] += 1
	}
}

func Encrypt(pp *PublicParams, id int, m *bls.Gt) *Ciphertext {
	// block index
	k := id / pp.blockSize
	idIndex := id % pp.blockSize
	hParamsG2 := pp.hParamsG2
	g2 := pp.g2
	com := pp.commitments[k]

	r := randomScalar()

	ct0 := com

	ct1 := bls.Pair(com, hParamsG2[pp.blockSize-1-idIndex])
	ct1.Exp(ct1, r)

	ct2 := new(bls.G2)
	ct2.ScalarMult(r, g2)

	ct3 := bls.Pair(pp.hParamsG1[idIndex], hParamsG2[pp.blockSize-1-idIndex])
	ct3.Exp(ct3, r)
	ct3.Mul(ct3, m)

	ct := &Ciphertext{ct0, ct1, ct2, ct3}
	return ct
}

func Update(pp *PublicParams, id int) []*bls.G1 {
	mu.UNUSED(pp)
	mu.UNUSED(id)
	return nil

}

func Decrypt(pp *PublicParams, id int, sk *bls.Scalar, updates []*bls.G1, ct *Ciphertext, updateIndex int) (*bls.Gt, error) {
	u := updates[updateIndex]
	idIndex := id % pp.blockSize

	t1 := bls.Pair(ct.ct0, pp.hParamsG2[pp.blockSize-1-idIndex])

	t2 := bls.Pair(u, pp.g2)
	x := new(bls.G1)
	x.ScalarMult(sk, pp.hParamsG1[idIndex])
	z := bls.Pair(x, pp.hParamsG2[pp.blockSize-1-idIndex])
	t2.Mul(t2, z)

	if !t1.IsEqual(t2) {
		return nil, ErrDecrypt
	}

	z = bls.Pair(u, ct.ct2)
	z.Inv(z)
	z.Mul(z, ct.ct1)
	w := new(bls.Scalar)
	w.Inv(sk)
	z.Exp(z, w)
	z.Inv(z)

	m := new(bls.Gt)
	m.Mul(ct.ct3, z)

	return m, nil
}
