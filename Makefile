maxusers= 100
timeout= 12h
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
	go test -v -bench=. -benchmem -timeout=$(timeout) -args -max-users=$(maxusers) 

clean:
	rm -f $(progs)

.PHONY: $(progs) all fmt vet test clean

# go test -v -bench=BenchmarkRegisterUser -benchmem -timeout=12h -args -max-users=1000000 
# go test -v -bench=BenchmarkNewKeyPair -benchmem -timeout=12h -args -max-users=1000000 

