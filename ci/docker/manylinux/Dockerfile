FROM quay.io/pypa/manylinux2010_x86_64

ENV OPENSSL openssl-1.1.1g
ENV LIBSSH 0.9.5
ENV SYSTEM_LIBSSH 1

RUN yum install zlib-devel cmake3 -y

ADD libssh-${LIBSSH}.tar.xz libssh.tar.xz
ADD https://www.openssl.org/source/${OPENSSL}.tar.gz ${OPENSSL}.tar.gz
ADD krb5-1.18.2.tar.gz krb5-1.18.2.tar.gz

RUN tar -xzf ${OPENSSL}.tar.gz
# Openssl
RUN cd ${OPENSSL} && \
    ./config --prefix=/usr --openssldir=/usr/openssl threads shared && \
    make -j6 && make install

# Kerberos
RUN cd krb5-1.18.2.tar.gz/krb5-1.18.2/src && \
    ./configure && \
    make -j6 && \
    make install

# Libssh
RUN mkdir -p build_libssh && cd build_libssh && \
    cmake3 ../libssh.tar.xz/libssh-${LIBSSH} -DCMAKE_BUILD_TYPE=Release \
          -DWITH_GSS_API=ON && \
    make -j6 install

RUN rm -rf ${OPENSSL}* libssh build_libssh krb5-1.18.2.tar.gz

VOLUME /var/cache
