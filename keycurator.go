package rbe

import (
	"fmt"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

type KeyCurator struct {
	PP *PublicParams

	// openings

	// indexed by the block number; stores the number of parties registered in
	// each block.  The paper calls this `aux` and the code calls this `aux_count`
	usersInBlock []int

	// len=maxUsers; the opening value for each user (indexed by the user's
	// id).  Ths is also called `aux` or `\Lambda`.  Each entry is a list of
	// history of lambdas (the current is the last entry in the list)
	UserOpenings [][]*bls.G1
}

func NewKeyCurator(pp *PublicParams) *KeyCurator {
	kc := new(KeyCurator)
	kc.PP = pp

	kc.usersInBlock = make([]int, pp.numBlocks)

	kc.UserOpenings = make([][]*bls.G1, pp.maxUsers)
	for i := 0; i < pp.maxUsers; i++ {
		kc.UserOpenings[i] = append(kc.UserOpenings[i], new(bls.G1))
		kc.UserOpenings[i][0].SetIdentity()
	}

	return kc
}

func (kc *KeyCurator) RegisterUser(id int, pk *bls.G1, xi []*bls.G1) {
	pp := kc.PP
	pp.CheckIdRange(id)

	k := pp.IdToBlock(id)
	idBar := pp.IdToIdBar(id)

	pp.CheckXiConsistency(pk, xi)

	// update commitment
	com := pp.Commitments[k]
	com.Add(com, pk)

	// update openings for the other users in that block
	for jBar := 0; jBar < pp.blockSize; jBar++ {
		if jBar == idBar {
			// don't update the registering id's opening
			continue
		}

		jId := pp.IdBarToId(jBar, k)
		jOpenings := kc.UserOpenings[jId]
		lastOpening := jOpenings[len(jOpenings)-1]

		newOpening := new(bls.G1)
		newOpening.Add(lastOpening, xi[jBar])

		jOpenings = append(jOpenings, newOpening)
		kc.UserOpenings[jId] = jOpenings
	}

	kc.usersInBlock[k] += 1
}

func (kc *KeyCurator) String() string {
	return fmt.Sprintf("usersInBlock: %v", kc.usersInBlock)
}
