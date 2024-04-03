FROM golang:latest as builder
COPY . /src
RUN cd /src && \
    GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -o ./build/main main.go

# =====
FROM ubuntu:latest
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /src/pkg/vsm/libgvsm/linux64/libTassSDF4GHVSM.so /usr/lib/libTassSDF4GHVSM.so
COPY --from=builder /src/pkg/vsm/libgvsm/cfg/tassConfig.ini /usr/etc/tassConfig.ini
COPY --from=builder /src/build/main /usr/bin/main
