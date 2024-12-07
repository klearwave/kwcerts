.PHONY: build
build:
	@go build -o bin/kwcerts internal/cmd/kwcerts/kwcerts.go

ca: build
	@mkdir -p tmp
	@bin/kwcerts create ca --ca-key=tmp/ca.key --ca-cert=tmp/ca.crt --force

ca-read: build
	@bin/kwcerts read cert --cert-file=tmp/ca.crt