import os

from sys import stderr
from subprocess import check_call
from glob import glob
from shutil import copy2
from multiprocessing import cpu_count


def build_ssh():
    if bool(os.environ.get('SYSTEM_LIBSSH', False)):
        stderr.write("Using system libssh..%s" % (os.sep))
        return
    if os.path.exists('/usr/local/opt/openssl'):
        os.environ['OPENSSL_ROOT_DIR'] = '/usr/local/opt/openssl'

    if not os.path.exists('src'):
        os.mkdir('src')
    if not os.path.exists('local'):
        os.mkdir('local')
    if not os.path.exists('local/lib'):
        os.mkdir('local/lib')
    # Depending on architecture cmake installs libraries into lib64,
    # but we don't care about that.
    if not os.path.exists('local/lib64'):
        os.symlink('lib', 'local/lib64')

    os.chdir('src')
    check_call('cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../local -DWITH_GSS_API=ON ../libssh',
               shell=True, env=os.environ)
    check_call(['make', '-j%s' % (cpu_count(),), 'all', 'install'])
    os.chdir('..')

    for src in glob('local/lib/libssh.so*'):
        copy2(src, 'ssh/')
