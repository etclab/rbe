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

	// len=MaxUsers; the opening value for each user (indexed by the user's
	// id).  Ths is also called `aux` or `\Lambda`.  Each entry is a list of
	// history of lambdas (the current is the last entry in the list)
	UserOpenings [][]*bls.G1
}

func NewKeyCurator(pp *PublicParams) *KeyCurator {
	kc := new(KeyCurator)
	kc.PP = pp

	kc.usersInBlock = make([]int, pp.NumBlocks)

	kc.UserOpenings = make([][]*bls.G1, pp.MaxUsers)
	for i := 0; i < pp.MaxUsers; i++ {
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
	for jBar := 0; jBar < pp.BlockSize; jBar++ {
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

func (kc *KeyCurator) UnregisterUser(id int, pk *bls.G1, xi []*bls.G1) {
	pp := kc.PP
	pp.CheckIdRange(id)

	k := pp.IdToBlock(id)
	idBar := pp.IdToIdBar(id)

	pp.CheckXiConsistency(pk, xi)

	// update commitment -- substract pk from commitment
	com := pp.Commitments[k]
	negPk := copyG1(pk)
	negPk.Neg()
	com.Add(com, negPk)

	// update openings for the other users in that block
	for jBar := 0; jBar < pp.BlockSize; jBar++ {
		if jBar == idBar {
			// don't update the registering id's opening
			continue
		}

		jId := pp.IdBarToId(jBar, k)
		jOpenings := kc.UserOpenings[jId]
		lastOpening := jOpenings[len(jOpenings)-1]

		negXi := copyG1(xi[jBar])
		negXi.Neg()
		newOpening := new(bls.G1)
		newOpening.Add(lastOpening, negXi)

		jOpenings = append(jOpenings, newOpening)
		kc.UserOpenings[jId] = jOpenings
	}

	kc.usersInBlock[k] -= 1
}

func (kc *KeyCurator) ProveMembership(id int, pk *bls.G1) *bls.G1 {
	pp := kc.PP
	pp.CheckIdRange(id)

	openings := kc.UserOpenings[id]
	lastOpening := openings[len(openings)-1]

	return lastOpening
}

func (kc *KeyCurator) String() string {
	return fmt.Sprintf("usersInBlock: %v", kc.usersInBlock)
}
