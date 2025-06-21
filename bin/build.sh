#!/bin/bash

mkdir -p ./dist

service_name="auth_service"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "./dist/$service_name" ../cmd/
wait

VERSION=$(cat ../VERSION)
echo "Building Docker image for $service_name:$VERSION" >/dev/stderr
docker build -t "$service_name:$VERSION" --build-arg BIN_NAME=$service_name -f ../Dockerfile ../

echo "removing dist folder in local" >/dev/stderr
rm -r dist
