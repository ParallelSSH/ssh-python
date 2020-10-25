#!/bin/bash -xe

docker_tag="parallelssh/ssh-manylinux"

rm -rf local build ssh/libssh.* ssh/*.so
python ci/appveyor/fix_version.py .

docker pull $docker_tag || echo
docker build --pull --cache-from $docker_tag ci/docker/manylinux -t $docker_tag
if [[ -z "$CIRCLE_PULL_REQUEST" ]]; then docker push $docker_tag; fi
docker run --rm -v `pwd`:/io $docker_tag /io/ci/build-wheels.sh
ls wheelhouse/
