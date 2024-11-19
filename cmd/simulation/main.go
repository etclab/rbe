package main

import (
	"github.com/etclab/mu"
	"github.com/etclab/rbe"
)

func main() {
	maxUsers := 4

	pp := rbe.NewPublicParams(maxUsers)
	kc := rbe.NewKeyCurator(pp)

	users := make([]*rbe.Users, maxUsers)
	for i = 0; i < maxUsers; i++ {
		user := rbe.NewUser(pp, i)
		users[i] = user
		// TODO: kc.RegisterUser()
	}

	// TODO: update each users opening

}
