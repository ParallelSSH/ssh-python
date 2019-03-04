from platform import python_version_tuple, system
if system() == 'Windows' and python_version_tuple()[0] < 3:
    raise ImportError("ssh-python for Python 2 on Windows is unsupported. Upgrade to Python 3.")
del python_version_tuple, system
