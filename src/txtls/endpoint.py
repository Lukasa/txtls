# -*- coding: utf-8 -*-
from __future__ import absolute_import

from zope.interface import implementer

from twisted.internet.interfaces import IStreamClientEndpoint

from .factory import NativeMemoryTLSFactory


@implementer(IStreamClientEndpoint)
class PEP543ClientEndpoint(object):
    """
    An endpoint that takes an existing client stream endpoint and wraps it in
    native TLS using PEP 543.
    """
    _wrapperFactory = NativeMemoryTLSFactory

    def __init__(self, wrappedEndpoint, configuration, backend, hostname):
        self._wrappedEndpoint = wrappedEndpoint
        self._configuration = configuration
        self._backend = backend
        self._hostname = hostname


    def connect(self, protocolFactory):
        """
        Connect the given protocol factory and unwrap its result.
        """
        return self._wrappedEndpoint.connect(
            self._wrapperFactory(
                configuration=self._configuration,
                isClient=True,
                wrappedFactory=protocolFactory,
                backend=self._backend,
                hostname=self._hostname,
            )
        ).addCallback(lambda protocol: protocol.wrappedProtocol)


# TODO: Server endpoint!
