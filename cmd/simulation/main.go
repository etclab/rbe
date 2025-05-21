package main

import (
	"fmt"

	"github.com/etclab/mu"
	"github.com/etclab/rbe"
)

func main() {
	maxUsers := 4

	pp := rbe.NewPublicParams(maxUsers)
	fmt.Println(pp)
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
	msg := rbe.RandomGt()
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
