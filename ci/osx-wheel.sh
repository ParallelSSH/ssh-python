#!/bin/bash -xe

python -m pip install -U virtualenv
python -m virtualenv -p "$(which python)" venv

set +x
source venv/bin/activate
set -x

python -V
python -m pip install -U setuptools pip
pip install -U delocate wheel
pip wheel .
ls -lhtr /usr/local/lib/
# cp /usr/local/lib/libssh* .
delocate-listdeps --all *.whl
delocate-wheel -v *.whl
delocate-listdeps --all *.whl

ls -l *.whl
rm -f *.dylib
pip install -v *.whl
pwd; mkdir -p temp; cd temp; pwd
python -c "from ssh.session import Session; Session()" && echo "Import successfull"
cd ..; pwd
set +x
deactivate
set -x

mv -f *.whl wheels/
ls -lh wheels
