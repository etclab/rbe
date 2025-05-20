package rbe_test

import (
	"flag"
	"fmt"
	"math"
	"os"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/rbe"
)

var (
	MaxUsers     int
	SqrtMaxUsers int
)

const (
	kSendingUserId   = 2
	kReceivingUserId = 3
)

func setupSystem(maxUsers int) (*rbe.PublicParams, *rbe.KeyCurator, []*rbe.User) {
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
	coms := kc.PP.Commitments
	for id := 0; id < maxUsers; id++ {
		opening := kc.UserOpenings[id]
		users[id].Update(coms, opening)
	}

	return pp, kc, users
}

func createDummyMessage() *bls.Gt {
	return rbe.RandomGt()
}

func TestDecrypt(t *testing.T) {
	_, _, users := setupSystem(MaxUsers)
	sender := users[kSendingUserId]
	receiver := users[kReceivingUserId]
	msg := createDummyMessage()
	ct := sender.Encrypt(kReceivingUserId, msg)
	plain, err := receiver.Decrypt(ct)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !msg.IsEqual(plain) {
		t.Fatalf("decrypted plaintext does not equal the original message")
	}
}

func TestVerifyMembership(t *testing.T) {
	pp, kc, users := setupSystem(MaxUsers)
	u := users[kSendingUserId]
	proof := kc.ProveMembership(u.Id())
	result := rbe.VerifyMembership(pp, u.Id(), u.PublicKey(), proof)
	if !result {
		t.Fatalf("rbe.VerifyMembership returned false for registered user")
	}
}

func BenchmarkNewKeyPair(b *testing.B) {
	for i := 2; i <= SqrtMaxUsers; i++ {
		maxUsers := i * i
		pp := rbe.NewPublicParams(maxUsers)
		b.Run(fmt.Sprintf("NewKeyPair-%d", maxUsers), func(b *testing.B) {
			for b.Loop() {
				_ = rbe.NewKeyPair(pp, kSendingUserId, nil)
			}
		})
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for i := 2; i <= SqrtMaxUsers; i++ {
		maxUsers := i * i
		_, _, users := setupSystem(maxUsers)
		msg := createDummyMessage()
		sender := users[kSendingUserId]
		b.Run(fmt.Sprintf("Encrypt-%d", maxUsers), func(b *testing.B) {
			for b.Loop() {
				_ = sender.Encrypt(kReceivingUserId, msg)
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for i := 2; i <= SqrtMaxUsers; i++ {
		maxUsers := i * i
		_, _, users := setupSystem(maxUsers)
		msg := createDummyMessage()
		sender := users[kSendingUserId]
		receiver := users[kReceivingUserId]
		ct := sender.Encrypt(kReceivingUserId, msg)
		b.Run(fmt.Sprintf("Decrypt-%d", maxUsers), func(b *testing.B) {
			for b.Loop() {
				_, err := receiver.Decrypt(ct)
				if err != nil {
					b.Fatalf("decrypt failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkRegisterUser(b *testing.B) {
	for i := 2; i <= SqrtMaxUsers; i++ {
		maxUsers := i * i
		pp := rbe.NewPublicParams(maxUsers)
		kc := rbe.NewKeyCurator(pp)
		u := rbe.NewUser(pp, kSendingUserId)
		b.Run(fmt.Sprintf("RegisterUser-%d", maxUsers), func(b *testing.B) {
			for b.Loop() {
				kc.RegisterUser(u.Id(), u.PublicKey(), u.Xi())
				b.StopTimer()
				kc.UnregisterUser(u.Id(), u.PublicKey(), u.Xi())
				b.StartTimer()
			}
		})
	}
}

func BenchmarkProveMembership(b *testing.B) {
	for i := 2; i <= SqrtMaxUsers; i++ {
		maxUsers := i * i
		pp := rbe.NewPublicParams(maxUsers)
		kc := rbe.NewKeyCurator(pp)
		id := 3
		u := rbe.NewUser(pp, id)
		kc.RegisterUser(3, u.PublicKey(), u.Xi())
		b.Run(fmt.Sprintf("ProveMembership-%d", maxUsers), func(b *testing.B) {
			for b.Loop() {
				_ = kc.ProveMembership(id)
			}
		})
	}
}

func BenchmarkVerifyMembership(b *testing.B) {
	for i := 2; i <= SqrtMaxUsers; i++ {
		maxUsers := i * i
		pp := rbe.NewPublicParams(maxUsers)
		kc := rbe.NewKeyCurator(pp)
		u := rbe.NewUser(pp, kSendingUserId)
		kc.RegisterUser(u.Id(), u.PublicKey(), u.Xi())
		proof := kc.ProveMembership(u.Id())
		b.Run(fmt.Sprintf("VerifyMembership-%d", maxUsers), func(b *testing.B) {
			for b.Loop() {
				if !rbe.VerifyMembership(pp, u.Id(), u.PublicKey(), proof) {
					b.Fatalf("rbe.VerifyMembership failed for a registered user")
				}
			}
		})
	}
}

func TestMain(m *testing.M) {
	flag.IntVar(&MaxUsers, "max-users", 100, "Maximum number of users (but be a square")
	flag.Parse()
	SqrtMaxUsers = int(math.Sqrt(float64(MaxUsers)))
	fmt.Printf("MaxUsers=%d, SqrtMaxUsers=%d\n", MaxUsers, SqrtMaxUsers)

	status := m.Run()

	os.Exit(status)
}
