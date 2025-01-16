IF "%PYTHON_VERSION%" == "2.7" (exit 0)

mkdir src
cd src

cmake ..\libssh                                    ^
      -A x64                                       ^
      -DCMAKE_BUILD_TYPE=Release                   ^
      -DZLIB_LIBRARY=C:/zlib/lib/zlibstatic.lib    ^
      -DZLIB_INCLUDE_DIR=C:/zlib/include           ^
      -DWITH_GSSAPI=ON                             ^
      -DWITH_EXAMPLES=OFF                          ^
      -DUNIT_TESTING=OFF                           ^
      -DOPENSSL_ROOT_DIR=%OPENSSL_DIR%


dir %OPENSSL_DIR%\lib\VC\x64\MD\
cp %OPENSSL_DIR%\lib\VC\x64\MD\libcrypto.lib %APPVEYOR_BUILD_FOLDER%\libcrypto64MD.lib
cp %OPENSSL_DIR%\lib\VC\x64\MD\libssl.lib %APPVEYOR_BUILD_FOLDER%\libssl64MD.lib

cmake --build . --config Release
cmake --install . --prefix ../local

cd ..
