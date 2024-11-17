package main

import (
	"github.com/etclab/mu"
	"github.com/etclab/rbe"
)

func main() {
	pp := rbe.NewPublicParams(100)

	id := 54
	key, err := rbe.NewKeyPair(pp, id)
	if err != nil {
		mu.Fatalf("rbe.NewKeyPair failed: %v", err)
	}

	mu.UNUSED(key)
}
