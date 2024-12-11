#!/bin/sh
set -e
rm -rf completions
mkdir completions
for sh in bash zsh fish; do
	go run ./internal/cmd/kwcerts completion "$sh" >"completions/kwcerts.$sh"
done
