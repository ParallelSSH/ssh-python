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
