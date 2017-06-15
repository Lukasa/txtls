# -*- coding: utf-8 -*-
from __future__ import absolute_import

import pep543

from twisted.internet.interfaces import ILoggingContext
from twisted.protocols.policies import WrappingFactory

from .protocol import NativeMemoryTLSProtocol


class NativeMemoryTLSFactory(WrappingFactory):
    """
    A protocol factory that builds an intermediary transport that wraps a
    stream transport and exposes a stream transport interface. This
    substantially follows the design of Twisted's own TLSMemoryBIOFactory, but
    rather than relying directly on PyOpenSSL this supports PEP 543 to provide
    support for a wide range of TLS implementations.
    """
    # TODO: Add support for IProtocolNegotiationFactory.
    # TODO: Should a full PEP 543 configuration be provided here? Probably
    #       not. If not, then what?
    protocol = NativeMemoryTLSProtocol

    noisy = False  # disable unnecessary logging.

    def __init__(self, configuration, isClient, wrappedFactory, backend, hostname=None):
        """
        Create a NativeMemoryTLSFactory.

        :param configuration: A PEP 543 configuration object requesting
            specific TLS configuration.

        :param isClient: A boolean indicating whether this factory will be
            creating client side TLS implementations, or server-side ones.

        :param wrappedFactory: A factory which will create the
            application-level protocol.

        :param backend: A PEP 543 backend object to use to create the TLS.
            TODO: Make this optional and have a way to find the best choice.

        :param hostname: A server hostname to connect to, if needed.
        """
        # Sigh old-style classes.
        WrappingFactory.__init__(self, wrappedFactory)
        if isClient:
            self._context = backend.client_context(configuration)
        else:
            self._context = backend.server_context(configuration)
        self._hostname = hostname


    def logPrefix(self):
        """
        Annotate the wrapped factory's log prefix with some text indicating TLS
        is in use.
        """
        if ILoggingContext.providedBy(self.wrappedFactory):
            logPrefix = self.wrappedFactory.logPrefix()
        else:
            logPrefix = self.wrappedFactory.__class__.__name__
        return "%s (Native TLS)" % (logPrefix,)


    def _createConnection(self, tlsProtocol):
        """
        Create a TLS connection.

        :param tlsProtocol: The protocol which is establishing the connection.

        :param hostname: (optional) If connecting to a server, the hostname of
            the server for SNI and validation purposes.

        :return: A TLS connection object for C{tlsProtocol} to use
        """
        args = tuple()

        if self._hostname is not None:
            args = (self._hostname,)

        return self._context.wrap_buffers(*args)
