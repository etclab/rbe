package rbe

import (
	"sync"
	"testing"
)

func TestConcurrentRegisterDifferentBlocks(t *testing.T) {
	// Use 16 users (blockSize=4, numBlocks=4) so we have multiple blocks.
	maxUsers := 16
	pp := NewPublicParams(maxUsers)
	kc := NewKeyCurator(pp)

	if pp.NumBlocks < 2 {
		t.Fatalf("need at least 2 blocks for this test, got %d", pp.NumBlocks)
	}

	// Pre-create users (one per block) to register concurrently.
	type reg struct {
		user *User
	}
	var regs []reg
	for block := 0; block < pp.NumBlocks; block++ {
		id := block * pp.BlockSize // first id in each block
		u := NewUser(pp, id)
		regs = append(regs, reg{user: u})
	}

	// Register all users concurrently across different blocks.
	var wg sync.WaitGroup
	for _, r := range regs {
		wg.Add(1)
		go func(u *User) {
			defer wg.Done()
			kc.RegisterUser(u.Id(), u.PublicKey(), u.Xi())
		}(r.user)
	}
	wg.Wait()

	// Verify each registration succeeded via ProveMembership + VerifyMembership.
	for _, r := range regs {
		u := r.user
		proof := kc.ProveMembership(u.Id())
		if !VerifyMembership(pp, u.Id(), u.PublicKey(), proof) {
			t.Errorf("VerifyMembership failed for user %d after concurrent registration", u.Id())
		}
	}
}
