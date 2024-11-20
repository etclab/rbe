package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type User struct {
	pp      *PublicParams
	id      int
	keyPair *KeyPair

	// the history of openings for this user.  (most recent last)
	// This slice should never exceed a length of `blockSize
	// The paper/code also calls these `updates`
	openings []*bls.G1
}

func NewUser(pp *PublicParams, id int) *User {
	pp.CheckIdRange(id)

	u := new(User)
	u.pp = pp
	u.id = id
	u.keyPair = NewKeyPair(pp, id)

	return u
}

func (u *User) PublicKey() *bls.G1 {
	return u.keyPair.PublicKey
}

func (u *User) Xi() []*bls.G1 {
	return u.keyPair.Xi
}

func (u *User) Id() int {
	return u.id
}

func (u *User) Encrypt(recvId int, msg *bls.Gt) *Ciphertext {
	return Encrypt(u.pp, recvId, msg)
}

func (u *User) Decrypt(ct *Ciphertext) (*bls.Gt, error) {
	// FIXME: we currently assume that the ciphertext was encrypted using the
	// last opening that the user has; we should really loop over all openings,
	// which is what the efficientRBE repo does

	pp := u.pp
	hParamsG1 := pp.crs.hParamsG1
	hParamsG2 := pp.crs.hParamsG2
	sk := u.keyPair.SecretKey

	opening := u.openings[len(u.openings)-1]
	idBar := pp.IdToIdBar(u.id)

	t1 := bls.Pair(ct.ct0, hParamsG2[pp.blockSize-1-idBar])

	t2 := bls.Pair(opening, pp.g2)
	x := new(bls.G1)
	x.ScalarMult(sk, hParamsG1[idBar])
	z := bls.Pair(x, hParamsG2[pp.blockSize-1-idBar])
	t2.Mul(t2, z)

	if !t1.IsEqual(t2) {
		return nil, ErrDecrypt
	}

	z = bls.Pair(opening, ct.ct2)
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

func (u *User) Update(newCommitments, newOpenings []*bls.G1) {
	u.pp.Commitments = newCommitments
	u.openings = newOpenings
}
