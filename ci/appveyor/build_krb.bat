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

refreshenv
set KRB_INSTALL_DIR=%APPVEYOR_HOME_DIR%/src/lib
set CPU=AMD64
setenv /x64 /release
cd krb-1.21.3/src
make -f Makefile.in prep-windows
make
make install
cd ../..
