.PHONY: build
build:
	@go build -o bin/kwcerts internal/cmd/kwcerts/kwcerts.go

docker-build:
	@docker build . -t ghcr.io/klearwave/kwcerts:latest

docker-push:
	@docker push ghcr.io/klearwave/kwcerts:latest

ca: build
	@mkdir -p tmp
	@bin/kwcerts create ca --ca-key=tmp/ca.key --ca-cert=tmp/ca.crt --force

ca-read: build
	@bin/kwcerts read cert --cert-file=tmp/ca.crt

cert:
	@bin/kwcerts create certificate \
		--bits=4096 \
		--days=3650 \
		--common-name="my-cert" \
		--ca-key=tmp/ca.key \
		--ca-cert=tmp/ca.crt \
		--key=tmp/server.key \
		--cert=tmp/server.crt

cert-kubernetes:
	@bin/kwcerts create certificate \
		--bits=4096 \
		--days=3650 \
		--common-name="my-cert" \
		--ca-key=tmp/ca.key \
		--ca-cert=tmp/ca.crt \
		--key=tmp/server.key \
		--cert=tmp/server.crt \
		--kubernetes-service-name=test \
		--kubernetes-service-namespace=default

cert-read:
	@bin/kwcerts read cert --cert-file=tmp/server.crt