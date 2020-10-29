.PHONY: test coverhtml

test:
	go test -v --race .

coverhtml:
	@mkdir -p coverage
	@go test -coverprofile=coverage/cover.out .
	@go tool cover -html=coverage/cover.out -o coverage/coverage.html
	@go tool cover -func=coverage/cover.out | tail -n 1

.PHONY: build-darwin build-linux
build-darwin:
	@mkdir -p ./dist/darwin
	GO111MODULE=on CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o ./dist/darwin/otgo ./cmd/otgo/main.go
build-linux:
	@mkdir -p ./dist/linux
	GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ./dist/linux/otgo ./cmd/otgo/main.go