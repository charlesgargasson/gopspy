FROM golang:latest
RUN \
apt update && apt install -y gcc-mingw-w64
COPY go.mod /src/go.mod
WORKDIR /src
RUN go mod download
