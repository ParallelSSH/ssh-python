#  This file is part of ssh-python.
#  Copyright (C) 2018-2025 Panos Kittenis.
#  Copyright (C) 2018-2025 ssh-python Contributors.
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation, version 2.1.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with this library; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-130

import sys
import subprocess
import os


def upload_pypi(files):
    repo_tag = os.environ.get('APPVEYOR_REPO_TAG', 'false')
    if repo_tag == 'false':
        sys.stderr.write("Not a tagged release, skipping upload" + os.linesep)
        return
    _user, _pass = os.environ.get('PYPI_USER'), os.environ.get('PYPI_PASS')
    if not _user or not _pass:
        sys.stderr.write("No PyPi credentials set" + os.linesep)
        sys.exit(1)
    proc = subprocess.run(['twine', 'upload', '-u', _user,
                           '-p', _pass, files])
    if proc.returncode:
        sys.stderr.write("Error uploading to PyPi" + os.linesep)
        sys.exit(1)


if __name__ == "__main__":
    if not len(sys.argv) > 1:
        sys.stderr.write("Need files to upload argument" + os.linesep)
        sys.exit(1)
    upload_pypi(os.path.abspath(sys.argv[1]))
