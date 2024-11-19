package rbe

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type KeyCurator struct {
	pp *PublicParams

	// openings

	// Commitment C for each block ; indexed by the block number
	commitments []*bls.G1 // in the paper, these are just called `pp`

	// indexed by the block number; stores the number of parties registered in
	// each block.  The paper calls this `aux` and the code calls this `aux_count`
	usersInBlock []int

	// len=maxUsers; the opening value for each user (indexed by the user's
	// id).  Ths is also called `aux` or `\Lambda`.  Each entry is a list of
	// history of lambdas (the current is the last entry in the list)
	userOpenings [][]*bls.G1
}

func NewKeyCurator(pp *PublicParams) *KeyCurator {
	kc := new(KeyCurator)
	kc.pp = pp

	kc.commitments = make([]*bls.G1, pp.numBlocks)
	for i := 0; i < pp.numBlocks; i++ {
		kc.commitments[i] = new(bls.G1)
		kc.commitments[i].SetIdentity()
	}

	kc.usersInBlock = make([]int, pp.numBlocks)

	kc.userOpenings = make([][]*bls.G1, pp.maxUsers)
	for i := 0; i < pp.maxUsers; i++ {
		kc.userOpenings[i] = append(kc.userOpenings[i], new(bls.G1))
		kc.userOpenings[i][0].SetIdentity()
	}

	return kc
}

func (kc *KeyCurator) RegisterUser(id int, pk *bls.G1, xi []*bls.G1) {
	pp := kc.pp
	pp.CheckIdRange(id)

	k := pp.IdToBlock(id)
	idBar := pp.IdToIdBar(id)

	pp.CheckXiConsistency(pk, xi)

	// update commitment
	com := kc.commitments[k]
	com.Add(com, pk)

	// update openings for the other uses in that block
	for jBar := 0; jBar < pp.blockSize; jBar++ {
		if jBar == idBar {
			// don't update the registering id's opening
			continue
		}

		jId := pp.IdBarToId(jBar, k)
		jOpenings := kc.userOpenings[jId]
		lastOpening := jOpenings[len(jOpenings)-1]

		newOpening := new(bls.G1)
		newOpening.Add(lastOpening, xi[jBar])

		jOpenings = append(jOpenings, newOpening)
		kc.userOpenings[jId] = jOpenings

	}

	kc.usersInBlock[k] += 1
}
