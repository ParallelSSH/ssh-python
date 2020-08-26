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
