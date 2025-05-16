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

func BenchmarkProveMembership(b *testing.B) {

}

func BenchmarkVerifyMembership(b *testing.B) {

}
*/
