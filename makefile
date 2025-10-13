sec:
	gosec ./...

.PHONY: check-coverage
check-coverage:
	-rm -rf ./cover.out
	go test ./... -coverprofile=./cover.out -covermode=atomic -coverpkg=./...
	go-test-coverage --config=./.testcoverage.yml