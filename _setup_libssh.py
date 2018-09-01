from subprocess import check_call
import os
from glob import glob
from shutil import copy2
from multiprocessing import cpu_count


def build_ssh():
    if os.path.exists('/usr/local/opt/openssl'):
        os.environ['OPENSSL_ROOT_DIR'] = '/usr/local/opt/openssl'

    if not os.path.exists('src'):
        os.mkdir('src')

    os.chdir('src')
    check_call('cmake -DCMAKE_BUILD_TYPE=Release ../libssh',
               shell=True, env=os.environ)
    check_call(['make', '-j%s' % (cpu_count(),)])
    os.chdir('..')

    for src in glob('src/src/libssh.so*'):
        copy2(src, 'ssh/')
