# This file is part of ssh-python.
# Copyright (C) 2017-2022 Panos Kittenis and contributors.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, version 2.1.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
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
    check_call("""cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../local \
    -DWITH_GSSAPI=ON \
    -DWITH_EXAMPLES=OFF \
    ../libssh""",
               shell=True, env=os.environ)
    check_call(['make', '-j%s' % (cpu_count(),), 'all', 'install'])
    os.chdir('..')

    for src in glob('local/lib/libssh.so*'):
        copy2(src, 'ssh/')
