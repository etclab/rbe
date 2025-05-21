maxusers= 100

progs= simulation

all: $(progs)

$(progs): vet
	go build ./cmd/$@

vet: fmt
	go vet ./...

fmt:
	go fmt ./...

# -count=1 forces tests to always run, even if no code has changed
test:
	go test -v -vet=all -count=1 ./... -args -max-users=$(maxusers)

benchmark: fmt
	go test -v -bench=. -benchmem -args -max-users=$(maxusers)

clean:
	rm -f $(progs)

.PHONY: $(progs) all fmt vet test clean
