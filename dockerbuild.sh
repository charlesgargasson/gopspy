#!/bin/bash
cd -- "$(dirname -- "$0")"

docker inspect --type=image gopspy_builder >/dev/null 2>&1
if [ $? -ne 0 ];then
    docker build -t gopspy_builder:latest .
    docker inspect --type=image gopspy_builder >/dev/null 2>&1
    if [ $? -ne 0 ];then
        echo "IMAGE ERROR"
        exit 1
    fi
fi

docker run --rm -it -v "$(pwd):/workspace/" gopspy_builder:latest bash /workspace/build.sh
find bin/ -type f
