@REM This file is part of ssh-python.
@REM Copyright (C) 2018-2025 Panos Kittenis.
@REM Copyright (C) 2018-2025 ssh-python Contributors.
@REM
@REM This library is free software; you can redistribute it and/or
@REM modify it under the terms of the GNU Lesser General Public
@REM License as published by the Free Software Foundation, version 2.1.
@REM
@REM This library is distributed in the hope that it will be useful,
@REM but WITHOUT ANY WARRANTY; without even the implied warranty of
@REM MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
@REM Lesser General Public License for more details.
@REM
@REM You should have received a copy of the GNU Lesser General Public
@REM License along with this library; if not, write to the Free Software
@REM Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-130

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
