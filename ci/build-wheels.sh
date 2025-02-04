#!/bin/bash -xe
# This file is part of ssh-python.
# Copyright (C) 2017-2022 Panos Kittenis and contributors.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, version 2.1.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

# Compile wheels
rm -rf /io/build
# For testing
#for PYBIN in $(ls -1d /opt/python/cp310-cp310/bin | grep -v cpython); do
for PYBIN in $(ls -1d /opt/python/*/bin | grep -v cpython | grep -v cp313t); do
    echo "Building for Python binary ${PYBIN}"
    "${PYBIN}/pip" wheel /io/ -w wheelhouse/
done

# Bundle external shared libraries into the wheels
for whl in wheelhouse/*.whl; do
#    auditwheel show "$whl"
    auditwheel repair "$whl" -w /io/wheelhouse/
    auditwheel show "$whl"
done

# Install packages and test
for PYBIN in $(ls -1d /opt/python/*/bin | grep -v cpython | grep -v cp313t); do
# for PYBIN in `ls -1d /opt/python/cp310-cp310/bin | grep -v cpython`; do
    echo "Installing for Python binary ${PYBIN}"
    "${PYBIN}/pip" install ssh-python --no-index -f /io/wheelhouse
    (cd "$HOME"; "${PYBIN}/python" -c 'from ssh.session import Session; Session()' &&
    echo "Import sanity check succeeded.")
done
