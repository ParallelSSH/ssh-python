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

from __future__ import print_function
import sys

from platform import python_version_tuple, system
try:
    from ssh.session import Session
except ImportError as ex:
    if system() == 'Windows' and python_version_tuple()[0] == "2":
        import ssh
        print("Python 2 on Windows - import error {} raised".format(ex))
        sys.exit(0)
    print("{} {}".format(system(), python_version_tuple()[0]))
    raise
else:
    print("Import successful")
