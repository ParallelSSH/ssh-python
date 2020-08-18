cd "openssl-%OPENSSL_VER%"

perl Configure VC-WIN64A --no-shared
nmake
dumpbin /headers libcrypto-1_1x64.dll
ls libcrypto*
cp libcrypto* ../
cd ..
