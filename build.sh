#!/bin/bash
cd -- "$(dirname -- "$0")"
VCS="-buildvcs=false"
go version
go get main
set -x
env GOOS=windows GOARCH=amd64 CGO_ENABLED=0 CC=x86_64-w64-mingw32-gcc go build -o bin/gopspy.exe $VCS
env GOOS=windows GOARCH=386 CGO_ENABLED=0 CC=x86_64-w64-mingw32-gcc go build -o bin/gopspy32.exe $VCS
