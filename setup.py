import platform
import os
import sys
from glob import glob
from _setup_libssh import build_ssh

import versioneer
from setuptools import setup, find_packages

cpython = platform.python_implementation() == 'CPython'

try:
    from Cython.Distutils.extension import Extension
    from Cython.Distutils import build_ext
except ImportError:
    from setuptools import Extension
    USING_CYTHON = False
else:
    USING_CYTHON = True

_PYTHON_MAJOR_VERSION = int(platform.python_version_tuple()[0])
ON_WINDOWS = platform.system() == 'Windows'
SYSTEM_LIBSSH = bool(os.environ.get('SYSTEM_LIBSSH', 0))

if ON_WINDOWS and _PYTHON_MAJOR_VERSION < 3:
    raise ImportError(
        "ssh-python requires Python 3 or above on Windows platforms.")

# Only build libssh if running a build
if (len(sys.argv) >= 2 and not (
        '--help' in sys.argv[1:] or
        sys.argv[1] in (
            '--help-commands', 'egg_info', '--version', 'clean',
            'sdist', '--long-description')) and
        __name__ == '__main__'):
    if not (ON_WINDOWS and _PYTHON_MAJOR_VERSION != 2):
        build_ssh()

ext = 'pyx' if USING_CYTHON else 'c'
sources = glob('ssh/*.%s' % (ext,))
_arch = platform.architecture()[0][0:2]
_libs = ['ssh'] if not ON_WINDOWS else [
    'ssh', 'Ws2_32', 'user32',
    'libcrypto%sMD' % _arch, 'libssl%sMD' % _arch,
    'zlibstatic',
]

# _comp_args = ["-ggdb"]
_comp_args = ["-O3"] if not ON_WINDOWS else None
cython_directives = {
    'embedsignature': True,
    'boundscheck': False,
    'optimize.use_switch': True,
    'wraparound': False,
}
cython_args = {
    'cython_directives': cython_directives,
    'cython_compile_time_env': {
        'ON_WINDOWS': ON_WINDOWS,
    }} \
    if USING_CYTHON else {}


runtime_library_dirs = ["$ORIGIN/."] if not SYSTEM_LIBSSH else None
_lib_dir = os.path.abspath("./src/lib") if not SYSTEM_LIBSSH else "/usr/local/lib"
include_dirs = ["libssh/include"] if ON_WINDOWS or not SYSTEM_LIBSSH else ["/usr/local/include"]

extensions = [
    Extension(
        sources[i].split('.')[0].replace(os.path.sep, '.'),
        sources=[sources[i]],
        include_dirs=include_dirs,
        libraries=_libs,
        library_dirs=[_lib_dir],
        runtime_library_dirs=runtime_library_dirs,
        extra_compile_args=_comp_args,
        **cython_args
    )
    for i in range(len(sources))]

package_data = {'ssh': ['*.pxd', 'libssh.so*']}

if ON_WINDOWS:
    package_data['ssh'].extend([
        'libcrypto*.dll', 'libssl*.dll',
        'ssh.dll', 'msvc*.dll', 'vcruntime*.dll',
    ])

cmdclass = versioneer.get_cmdclass()
if USING_CYTHON:
    cmdclass['build_ext'] = build_ext
    sys.stdout.write("Cython arguments: %s%s" % (cython_args, os.linesep))


sys.stdout.write("Windows platform: %s, Python major version: %s.%s" % (ON_WINDOWS, _PYTHON_MAJOR_VERSION, os.sep))
if ON_WINDOWS and _PYTHON_MAJOR_VERSION == 2:
    # Python 2 on Windows builds are unsupported.
    extensions = [
        Extension(
            'ssh',
            sources=[os.sep.join(['ssh', '__init__.%s' % (ext,)])],
            extra_compile_args=_comp_args,
            **cython_args
        )
    ]
    package_data = {}
    sys.stdout.write("Windows Python 2 build - %s extensions: %s" % (len(extensions), os.sep))

setup(
    name='ssh-python',
    version=versioneer.get_version(),
    cmdclass=cmdclass,
    url='https://github.com/ParallelSSH/ssh-python',
    license='LGPLv2',
    author='Panos Kittenis',
    author_email='22e889d8@opayq.com',
    description=('libssh C library bindings for Python.'),
    long_description=open('README.rst').read(),
    packages=find_packages(
        '.', exclude=('embedded_server', 'embedded_server.*',
                      'tests', 'tests.*',
                      '*.tests', '*.tests.*')),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: C',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: System :: Shells',
        'Topic :: System :: Networking',
        'Topic :: Software Development :: Libraries',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: Linux',
        'Operating System :: POSIX :: BSD',
        'Operating System :: MacOS :: MacOS X',
    ],
    ext_modules=extensions,
    package_data=package_data,
)
