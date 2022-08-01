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
      -DOPENSSL_ROOT_DIR=%OPENSSL_DIR%


cp %OPENSSL_DIR%\lib\VC\libcrypto%PYTHON_ARCH%MD.lib %APPVEYOR_BUILD_FOLDER%
cp %OPENSSL_DIR%\lib\VC\libssl%PYTHON_ARCH%MD.lib %APPVEYOR_BUILD_FOLDER%

cmake --build . --config Release
cmake --install . --prefix ../local

cd ..
