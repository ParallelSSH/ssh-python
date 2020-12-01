ssh-python
============

Bindings for libssh_ C library.

.. image:: https://img.shields.io/badge/License-LGPL%20v2-blue.svg
   :target: https://pypi.python.org/pypi/ssh-python
   :alt: License
.. image:: https://img.shields.io/pypi/v/ssh-python.svg
   :target: https://pypi.python.org/pypi/ssh-python
   :alt: Latest Version
.. image:: https://circleci.com/gh/ParallelSSH/ssh-python/tree/master.svg?style=shield
   :target: https://circleci.com/gh/ParallelSSH/ssh-python/tree/master
.. image:: https://img.shields.io/pypi/wheel/ssh-python.svg
   :target: https://pypi.python.org/pypi/ssh-python
.. image:: https://img.shields.io/pypi/pyversions/ssh-python.svg
   :target: https://pypi.python.org/pypi/ssh-python
.. image:: https://ci.appveyor.com/api/projects/status/2t4bmmtjvfy5s1in/branch/master?svg=true
   :target: https://ci.appveyor.com/project/pkittenis/ssh-python
.. image:: https://readthedocs.org/projects/ssh-python/badge/?version=latest
   :target: http://ssh-python.readthedocs.org/en/latest/
   :alt: Latest documentation


Installation
_____________

Binary wheels are provided for Linux (manylinux 2010), OSX (10.14 and 10.15 for brew Python), and Windows 64-bit (Python 3.6/3.7/3.8).

Wheels have *no dependencies*.

For building from source, see `documentation <https://ssh-python.readthedocs.io/en/latest/installation.html#building-from-source>`_.


.. code-block:: shell

   pip install ssh-python

Pip may need to be updated to be able to install binary wheels.

.. code-block:: shell

   pip install -U pip
   pip install ssh-python


Quick Start
_____________

See `command execution script <https://github.com/ParallelSSH/ssh-python/blob/master/examples/exec.py>`_ for complete example.

Features
_________

The library uses `Cython`_ based native code extensions as wrappers to ``libssh``.

* Thread safe - GIL released as much as possible

  * libssh threading limitations apply - anything not supported in C is not supported in Python
* Very low overhead thin wrapper
* Object oriented

  * Memory freed automatically and safely as objects are garbage collected by Python
* Uses Python semantics where applicable

  * channel/file handle context manager support
  * channel/file handle iterator support
* Raises low level C errors as Python exceptions


.. _libssh: https://www.libssh.org
.. _Cython: https://www.cython.org
