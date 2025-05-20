package rbe_test

import (
	"fmt"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
)

const (
	kSendingUserId   = 2
	kReceivingUserId = 3
)

func TestVerifyMembership(t *testing.T) {
	pp := rbe.NewPublicParams(144)
	kc := rbe.NewKeyCurator(pp)
	u := rbe.NewUser(pp, kSendingUserId)
	kc.RegisterUser(u.Id(), u.PublicKey(), u.Xi())

	proof := kc.ProveMembership(u.Id())
	result := rbe.VerifyMembership(pp, u.Id(), u.PublicKey(), proof)
	if !result {
		t.Fatalf("rbe.VerifyMembership returned false for registered user")
	}
}

var blackholeKeyPair *rbe.KeyPair

func BenchmarkNewKeyPair(b *testing.B) {
	// FIXME: should be i <= 1000
	for i := 2; i <= 10; i++ {
		// maxUsers must always be a square; thus the max we test is 1 M users
		maxUsers := i * i
		pp := rbe.NewPublicParams(maxUsers)
		b.Run(fmt.Sprintf("NewKeyPair-%d", maxUsers), func(b *testing.B) {
			for j := 0; j < b.N; j++ {
				keyPair := rbe.NewKeyPair(pp, kSendingUserId, nil)
				// ensure compiler does not optimize away the call to
				// rbe.NewKeyPair()
				blackholeKeyPair = keyPair
			}
		})
	}
}

var blackholeCiphertext *rbe.Ciphertext

func BenchmarkEncrypt(b *testing.B) {
	// FIXME: should be i <= 1000
	for i := 2; i <= 10; i++ {
		// maxUsers must always be a square; thus the max we test is 1 M users
		maxUsers := i * i
		pp := rbe.NewPublicParams(maxUsers)
		kc := rbe.NewKeyCurator(pp)

		// register users
		users := make([]*rbe.User, maxUsers)
		for id := 0; id < maxUsers; id++ {
			u := rbe.NewUser(pp, id)
			kc.RegisterUser(id, u.PublicKey(), u.Xi())
			users[id] = u
		}

		// update each user with the system's commitments and their block's opening
		for id := 0; id < maxUsers; id++ {
			coms := kc.PP.Commitments
			opening := kc.UserOpenings[id]
			users[id].Update(coms, opening)
		}

		// Create a dummy message to encrypt
		msg := rbe.RandomGt()

		sender := users[kSendingUserId]
		// benchmark encryption
		b.Run(fmt.Sprintf("Encrypt-%d", maxUsers), func(b *testing.B) {
			for j := 0; j < b.N; j++ {
				ct := sender.Encrypt(kReceivingUserId, msg)
				// ensure compiler does not optimize away the call to Encrypt()
				blackholeCiphertext = ct
			}
		})
	}
}

var blackholePlaintext *bls.Gt

func BenchmarkDecrypt(b *testing.B) {
	// FIXME: should be i <= 1000
	for i := 2; i <= 10; i++ {
		// maxUsers must always be a square; thus the max we test is 1 M users
		maxUsers := i * i
		pp := rbe.NewPublicParams(maxUsers)
		kc := rbe.NewKeyCurator(pp)

		// register users
		users := make([]*rbe.User, maxUsers)
		for id := 0; id < maxUsers; id++ {
			u := rbe.NewUser(pp, id)
			kc.RegisterUser(id, u.PublicKey(), u.Xi())
			users[id] = u
		}

		// update each user with the system's commitments and their block's opening
		for id := 0; id < maxUsers; id++ {
			coms := kc.PP.Commitments
			opening := kc.UserOpenings[id]
			users[id].Update(coms, opening)
		}

		// Create and encrypt a dummy message
		msg := rbe.RandomGt()
		sender := users[kSendingUserId]
		receiver := users[kReceivingUserId]
		ct := sender.Encrypt(kReceivingUserId, msg)

		// benchmark encryption
		b.Run(fmt.Sprintf("Encrypt-%d", maxUsers), func(b *testing.B) {
			for j := 0; j < b.N; j++ {
				plain, err := receiver.Decrypt(ct)
				if err != nil {
					b.Fatalf("decrypt failed: %v", err)
				}
				// ensure compiler does not optimize away the call to Decrypt()
				blackholePlaintext = plain
			}
		})
	}

}

/*
func BenchmarkRegisterUser(b *testing.B) {
}
*/

var blackholeProof *bls.G1

func BenchmarkProveMembership(b *testing.B) {
	// FIXME: should be i <= 1000
	for i := 2; i <= 10; i++ {
		// maxUsers must always be a square; thus the max we test is 1 M users
		maxUsers := i * i
		pp := rbe.NewPublicParams(maxUsers)
		kc := rbe.NewKeyCurator(pp)
		id := 3
		u := rbe.NewUser(pp, id)
		kc.RegisterUser(3, u.PublicKey(), u.Xi())
		b.Run(fmt.Sprintf("ProveMembership-%d", maxUsers), func(b *testing.B) {
			for j := 0; j < b.N; j++ {
				proof := kc.ProveMembership(id)
				// ensure compiler does not optimize away the call to
				// kc.ProveMembership()
				blackholeProof = proof
			}
		})
	}
}

func BenchmarkVerifyMembership(b *testing.B) {
	// FIXME: should be i <= 1000
	for i := 2; i <= 10; i++ {
		// maxUsers must always be a square; thus the max we test is 1 M users
		maxUsers := i * i
		pp := rbe.NewPublicParams(maxUsers)
		kc := rbe.NewKeyCurator(pp)
		u := rbe.NewUser(pp, kSendingUserId)
		kc.RegisterUser(u.Id(), u.PublicKey(), u.Xi())
		proof := kc.ProveMembership(u.Id())
		b.Run(fmt.Sprintf("VerifyMembership-%d", maxUsers), func(b *testing.B) {
			for j := 0; j < b.N; j++ {
				if !rbe.VerifyMembership(pp, u.Id(), u.PublicKey(), proof) {
					b.Fatalf("rbe.VerifyMembership failed for a registered user")
				}
			}
		})
	}
}
