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


class SSHError(BaseSSHError):
    """Raised on errors returned by libssh.

    This is the general error libssh returns when any error
    occurs, whether that be server error or API error.

    Some functions like authentication have more specific error
    codes.
    """


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


class EOF(BaseSSHError):
    """Raised on EOF from remote channel"""


class InvalidAPIUse(BaseSSHError):
    """Raised on invalid uses of the API"""


class Disconnected(BaseSSHError):
    """Raised on disconnection errors"""


class UnImplemented(BaseSSHError):
    """Raised on unimplemented errors"""


class GSSAPIError(BaseSSHError):
    """Raised on GSS API errors"""


class GSSAPIErrorTok(BaseSSHError):
    """Raised on GSS API token errors"""


class RequestFailure(BaseSSHError):
    """Raised on SSH request failures"""


class ChannelOpenFailure(BaseSSHError):
    """Raised on SSH channel open failures"""


class HostNotAllowedToConnect(BaseSSHError):
    """Raised on host not allowed to connect errors"""


class ProtocolError(BaseSSHError):
    """Raised on protocol errors"""


class KeyExchangeFailed(BaseSSHError):
    """Raised on key exchange failures"""


class HostAuthenticationFailed(BaseSSHError):
    """Raised on host authentication failures"""


class MACError(BaseSSHError):
    """Raised on MAC errors"""


class CompressionError(BaseSSHError):
    """Raised on compression errors"""


class ServiceNotAvailable(BaseSSHError):
    """Raised on service not available errors"""


class ProtocolVersionNotSupport(BaseSSHError):
    """Raised on protocol version not supported"""


class HostKeyNotVerifiable(BaseSSHError):
    """Raised on host key not verifiable errors"""


class ConnectionLost(BaseSSHError):
    """Raised on connection lost"""


class TooManyConnections(BaseSSHError):
    """Raised on too many connection errors"""


class AdministrativelyProhibited(BaseSSHError):
    """Raised on administratively prohibited errors"""


class ConnectFailed(BaseSSHError):
    """Raised on connect failure"""


class UnknownChannelType(BaseSSHError):
    """Raised on unknown channel type"""


class ResourceShortage(BaseSSHError):
    """Raised on resource shortage errors"""


class SFTPError(BaseSSHError):
    """Raised on SFTP errors"""


class SFTPHandleError(SFTPError):
    """Raised on SFTP handle errors"""


class ChannelClosed(BaseSSHError):
    """Raised on operations on closed channels"""
