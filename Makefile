.PHONY: build
build:
	go build .

test:
	mkdir -p coverage/covdata
# Use the new binary format to ensure integration tests and cross-package calls are counted towards coverage
# https://go.dev/blog/integration-test-coverage
# -p 1 disable parallel testing in favor of streaming log output - https://github.com/golang/go/issues/24929#issuecomment-384484654
	go test -race -cover -covermode atomic -v -vet=all -timeout 15m -p 1\
		./... \
		-args -test.gocoverdir="${PWD}/coverage/covdata" \
		| ts -s
# NB: ts command requires moreutils package; awk trick from https://stackoverflow.com/a/25764579 doesn't stream output
	go tool covdata percent -i=./coverage/covdata
	# Convert to old text format for coveralls upload
	go tool covdata textfmt -i=./coverage/covdata -o ./coverage/covprofile
	go tool cover -html=./coverage/covprofile -o ./coverage/coverage.html

.PHONY: short-test
short-test:
	go test -v -short ./...

.PHONY: lint
lint:
	golangci-lint run -v


