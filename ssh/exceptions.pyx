# This file is part of ssh-python.
# Copyright (C) 2018 Panos Kittenis
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-130


class OptionError(Exception):
    """Raised on errors getting/setting options"""


class BaseSSHError(Exception):
    """Base class for all errors produced by libssh"""


class RequestDenied(BaseSSHError):
    """Raised on request denied by server errors"""


class FatalError(BaseSSHError):
    """Raised on unrecoverable errors"""


class OtherError(BaseSSHError):
    """Raised on other non-specific fatal errors"""


class AuthenticationDenied(BaseSSHError):
    """Raised on authentication denied errors"""


class AuthenticationError(BaseSSHError):
    """Raised on fatal errors authenticating"""


class AuthenticationPartial(BaseSSHError):
    """Raised on partial authentication"""


class KeyExportError(BaseSSHError):
    """Raised on errors exporting key"""


class KeyImportError(BaseSSHError):
    """Raised on errors importing key"""


class KeyGenerationError(BaseSSHError):
    """Raised on errors generating key"""


class SSHError(BaseSSHError):
    """Raised on SSH errors"""


class EOF(BaseSSHError):
    """Raised on EOF errors"""
