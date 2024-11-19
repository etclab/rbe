package main

import (
	"crypto/rand"
	"fmt"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/mu"
	"github.com/etclab/rbe"
)

func RandomScalar() *bls.Scalar {
	z := new(bls.Scalar)
	z.Random(rand.Reader)
	return z
}

func main() {
	maxUsers := 4

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

	fmt.Println(kc)
	for _, l := range kc.UserOpenings {
		fmt.Printf("%d: %v\n", len(l), l)
		fmt.Println()
	}

	// Test an encryption and decryption
	g1, g2 := pp.GetGenerators()
	z := RandomScalar()
	msg := bls.Pair(g1, g2)
	msg.Exp(msg, z)
	fmt.Println(msg)

	u2 := users[2]
	ct := u2.Encrypt(3, msg)

	u3 := users[3]
	plain, err := u3.Decrypt(ct)
	if err != nil {
		mu.Fatalf("decrypt failed: %v", err)
	}

	fmt.Println("------------------------------")
	fmt.Printf("%v\n", plain)
}
