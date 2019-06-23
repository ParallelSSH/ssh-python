from platform import python_version_tuple, system
if system() == 'Windows' and python_version_tuple()[0] == "2":
    raise ImportError("ssh-python for Python 2 on Windows is unsupported - "
                      "Python 3 or above is required.")
del python_version_tuple, system
