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
ADD krb5-1.18.2.tar.gz krb5-1.18.2.tar.gz


# Openssl
RUN cd ${OPENSSL}.tar.gz/${OPENSSL} && \
    ./config --prefix=/usr --openssldir=/usr/openssl threads shared && \
    make -j6 && make install

# Kerberos
RUN cd krb5-1.18.2.tar.gz/krb5-1.18.2/src && \
    ./configure && \
    make -j6 && \
    make install

# Libssh
RUN mkdir -p build_libssh && cd build_libssh && \
    cmake ../libssh.tar.gz/libssh -DCMAKE_BUILD_TYPE=Release -DWITH_GSS_API=ON && \
    make -j6 install


RUN rm -rf ${OPENSSL}* libssh build_libssh krb5-1.18.2.tar.gz


VOLUME /var/cache
