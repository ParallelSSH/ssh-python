#!/bin/bash -xe

if [ -d /usr/local/opt/openssl ]; then
    export OPENSSL_ROOT_DIR=/usr/local/opt/openssl
fi

mkdir -p src && cd src
cmake -DCMAKE_BUILD_TYPE=Release -DWITH_GSSAPI=ON ../libssh
make -j6
cd ..
cp src/src/libssh.so* ssh/
