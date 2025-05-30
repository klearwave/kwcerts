# Build the manager binary
FROM golang:1.23 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY pkg/ pkg/
COPY internal/ internal/

# Build
RUN CGO_ENABLED=0 go build -a -o kwcerts internal/cmd/kwcerts/kwcerts.go
RUN chmod +x kwcerts

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot
WORKDIR /
USER 65532:65532
COPY --from=builder /workspace/kwcerts /usr/bin/kwcerts

ENTRYPOINT ["/usr/bin/kwcerts"]
CMD ["--help"]
