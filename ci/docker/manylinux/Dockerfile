FROM quay.io/pypa/manylinux1_x86_64

ENV CMAKE cmake-2.8.11.1-5.4.x86_64
ENV OPENSSL openssl-1.0.2p
ENV LIBSSH 0.7.9
ENV SYSTEM_LIBSSH 1

RUN yum install zlib-devel -y

ADD ${CMAKE}.rpm cmake.rpm
RUN rpm -i cmake.rpm

ADD libssh-${LIBSSH}.tar.gz libssh.tar.gz
ADD ${OPENSSL}.tar.gz ${OPENSSL}.tar.gz


# Openssl
RUN cd ${OPENSSL}.tar.gz/${OPENSSL} && \
    ./config --prefix=/usr --openssldir=/usr/openssl threads shared && \
    make -j6 && make install


# Libssh
RUN mkdir -p build_libssh && cd build_libssh && \
    cmake ../libssh.tar.gz/libssh -DCMAKE_BUILD_TYPE=Release && \
    make -j6 install


RUN rm -rf ${OPENSSL}* libssh build_libssh


VOLUME /var/cache
