IF "%PYTHON_VERSION%" == "2.7" (exit 0)

mkdir src
cd src

set OPENSSL_DIR="C:\OpenSSL-v11-Win%PYTHON_ARCH%"

ls %OPENSSL_DIR%
ls %OPENSSL_DIR%\lib\VC
ls %OPENSSL_DIR%\lib\VC\static

IF "%MSVC%" == "Visual Studio 9" (
   ECHO "Building without platform set"
   set CMAKE_PLATFORM="NMake Makefiles"
) ELSE (
   ECHO "Building with platform %MSVC%"
   set CMAKE_PLATFORM="%MSVC%"
)

cmake ..\libssh  -G %CMAKE_PLATFORM%               ^
      -DCMAKE_BUILD_TYPE=Release                   ^
      -DZLIB_LIBRARY=C:/zlib/lib/zlibstatic.lib    ^
      -DZLIB_INCLUDE_DIR=C:/zlib/include           ^
      -DBUILD_STATIC_LIB=ON                        ^
      -DWITH_GSSAPI=ON                             ^
      -DOPENSSL_ROOT_DIR=%OPENSSL_DIR%


cp %OPENSSL_DIR%\lib\VC\libcrypto%PYTHON_ARCH%MD.lib %APPVEYOR_BUILD_FOLDER%
cp %OPENSSL_DIR%\lib\VC\libssl%PYTHON_ARCH%MD.lib %APPVEYOR_BUILD_FOLDER%

cmake --build . --config Release

cd ..
ECHO "libssh libs"
ls src/src/Release
cp src/src/Release/ssh.lib %PYTHON%/libs/
rem cp src/src/Release/* ssh/
ECHO "Python libs"
ls %PYTHON%/libs/
ECHO "ssh/ libs"
ls ssh/
