refreshenv
set KRB_INSTALL_DIR=%APPVEYOR_HOME_DIR%/src/lib
set CPU=AMD64
setenv /x64 /release
cd krb-1.21.3/src
make -f Makefile.in prep-windows
make
make install
cd ../..
