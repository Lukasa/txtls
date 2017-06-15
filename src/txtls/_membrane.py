# -*- coding: utf-8 -*-
from __future__ import absolute_import

from zope.interface import implementer

from twisted.internet.interfaces import IPushProducer


@implementer(IPushProducer)
class _ProducerMembrane(object):
    """
    Stand-in for producers registered with a NativeMemoryTLSProtocol transport.

    Ensures that producer pause/resume events from the undelying transport are
    coordinated with pause/resume events from the TLS layer, avoiding multiply
    pausing/resuming.
    """

    _producerPaused = False

    def __init__(self, producer):
        self._producer = producer


    def pauseProducing(self):
        """
        pauseProducing the underlying producer, if it's not paused.
        """
        if self._producerPaused:
            return
        self._producerPaused = True
        self._producer.pauseProducing()


    def resumeProducing(self):
        """
        resumeProducing the underlying producer, if it's paused.
        """
        if not self._producerPaused:
            return
        self._producerPaused = False
        self._producer.resumeProducing()


    def stopProducing(self):
        """
        stopProducing the underlying producer.

        There is only a single source for this event, so it's simply passed
        on.
        """
        self._producer.stopProducing()
