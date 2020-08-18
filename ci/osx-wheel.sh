#!/bin/bash -xe

pip3 install -U virtualenv
python3 -m virtualenv -p "$(which python3)" venv

set +x
source venv/bin/activate
set -x

python -V
pip3 install -U setuptools pip
pip3 install -U delocate wheel
pip3 wheel .
ls -lhtr /usr/local/lib/
# cp /usr/local/lib/libssh* .
delocate-listdeps --all *.whl
delocate-wheel -v *.whl
delocate-listdeps --all *.whl

ls -l *.whl
rm -f *.dylib
pip3 install -v *.whl
pwd; mkdir -p temp; cd temp; pwd
python -c "from ssh.session import Session; Session()" && echo "Import successfull"
cd ..; pwd
set +x
deactivate
set -x

mv -f *.whl wheels/
ls -lh wheels
