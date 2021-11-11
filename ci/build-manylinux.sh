#!/bin/bash -xe

docker_tag="parallelssh/ssh-manylinux"
docker_file="ci/docker/manylinux/Dockerfile"

rm -rf local build ssh/libssh.* ssh/*.so
python ci/appveyor/fix_version.py .

if [[ `uname -m` == "aarch64" ]]; then
    docker_tag=${docker_tag}-aarch64
    docker_file=${docker_file}.aarch64
fi

docker pull $docker_tag || echo
docker build --pull --cache-from $docker_tag ci/docker/manylinux -t $docker_tag -f ${docker_file}
if [[ -z "$CIRCLE_PR_NUMBER" ]]; then docker push $docker_tag; fi
docker run --rm -v `pwd`:/io $docker_tag /io/ci/build-wheels.sh
ls wheelhouse/
