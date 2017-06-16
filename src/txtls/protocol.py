# -*- coding: utf-8 -*-
from __future__ import absolute_import

import pep543

from zope.interface import providedBy, directlyProvides, implementer

from twisted.internet.interfaces import IHandshakeListener, INegotiated
from twisted.internet.protocol import Protocol
from twisted.protocols.policies import ProtocolWrapper
from twisted.python.failure import Failure

from ._membrane import _ProducerMembrane


# TODO: Implement any other interfaces TLSMemoryBIOProtocol has.
@implementer(INegotiated)
class NativeMemoryTLSProtocol(ProtocolWrapper):
    """
    A wrapping protocol that provides TLS using a platform-native TLS library
    via PEP 543. This is directly analagous to Twisted's TLSMemoryBIOProtocol,
    but using PEP 543's abstractions rather than talking directly to PyOpenSSL.
    """
    _reason = None
    _handshakeDone = False
    _lostTLSConnection = False
    _producer = None
    _aborted = False

    def makeConnection(self, transport):
        """
        Connect this wrapper to the given transport and initialize the
        necessary PEP 543 connection.
        """
        self._tlsConnection = self.factory._createConnection(self)

        # TODO: Is this better implemented as a bytearray?
        self._appSendBuffer = []

        # Add interfaces provided by the transport we are wrapping:
        for interface in providedBy(transport):
            directlyProvides(self, interface)

        # Intentionally skip ProtocolWrapper.makeConnection - it might call
        # wrappedProtocol.makeConnection, which we want to make conditional.
        Protocol.makeConnection(self, transport)
        self.factory.registerProtocol(self)

        # Now that the TLS layer is initialized, notify the application of
        # the connection. This is standard Twisted practice, despite being a
        # bit confusing: there is a separate interface that conforming
        # protocols can use if they care about when the handshake completes.
        ProtocolWrapper.makeConnection(self, transport)

        # Now that we ourselves have a transport (initialized by the
        # ProtocolWrapper.makeConnection call above), kick off the TLS
        # handshake.
        self._checkHandshakeStatus()


    def _checkHandshakeStatus(self):
        """
        Ask the TLS stack to proceed with a handshake in progress.
        """
        # The connection might already be aborted (eg. by a callback during
        # connection setup), so don't even bother trying to handshake in that
        # case.
        if self._aborted:
            return
        try:
            self._tlsConnection.do_handshake()
        except pep543.WantReadError:
            self._flushSendBuffers()
        except pep543.TLSError:
            self._tlsShutdownFinished(Failure())
        else:
            self._handshakeDone = True
            if IHandshakeListener.providedBy(self.wrappedProtocol):
                self.wrappedProtocol.handshakeCompleted()


    def _flushSendBuffers(self):
        """
        Read any bytes out of the send buffers and write them to the underlying
        transport.
        """
        # Don't do this if the TLS connection is gone.
        if self._lostTLSConnection:
            return

        dataLen = self._tlsConnection.bytes_buffered()
        if not dataLen:
            return

        # As Twisted has its own internal buffering, we are just going to pull
        # all the data out of the underlying TLS buffers and hand it to
        # Twisted.
        data = self._tlsConnection.peek_outgoing(dataLen)
        self._tlsConnection.consume_outgoing(dataLen)
        self.transport.write(data)


    def _flushReceiveBuffers(self):
        """
        Try to receive any application-level bytes which are now available
        because of a previous write into the receive buffers. This will take
        care of delivering any application-level bytes which are received to
        the protocol, as well as handling of the various exceptions which
        can come from trying to get such bytes.
        """
        # Keep trying this until an error indicates we should stop or we
        # close the connection.  Looping is necessary to make sure we
        # process all of the data which was put into the receive buffers, as
        # there is no guarantee that a single read call will do it all.
        while not self._lostTLSConnection:
            try:
                data = self._tlsConnection.read(2 ** 15)
            except pep543.WantReadError:
                # The newly received bytes might not have been enough to produce
                # any application data.
                break
            except pep543.TLSError:
                # Something went pretty wrong.  For example, this might be a
                # handshake failure during renegotiation (because there were no
                # shared ciphers, because a certificate failed to verify, etc).
                # TLS can no longer proceed.
                failure = Failure()
                self._tlsShutdownFinished(failure)
            else:
                if not data:
                    # Clean shutdown. No more TLS data will be received over
                    # this connection.
                    self._shutdownTLS()
                    # Passing in None means the user protocol's connnectionLost
                    # will get called with reason from underlying transport:
                    self._tlsShutdownFinished(None)
                elif not self._aborted and data:
                    ProtocolWrapper.dataReceived(self, data)

        # The received bytes might have generated a response which needs to be
        # sent now.  For example, the handshake involves several round-trip
        # exchanges without ever producing application-bytes.
        self._flushSendBuffers()


    def dataReceived(self, data):
        """
        Deliver any received bytes to the receive buffer and then read and
        deliver to the application any application-level data which becomes
        available as a result of this.
        """
        # Let the TLS layer know some bytes were just received.
        self._tlsConnection.receive_from_network(data)

        # If we are still waiting for the handshake to complete, try to
        # complete the handshake with the bytes we just received.
        if not self._handshakeDone:
            self._checkHandshakeStatus()

            # If the handshake still isn't finished, then we've nothing left to
            # do.
            if not self._handshakeDone:
                return

        # If we've any pending writes, this read may have un-blocked them, so
        # attempt to unbuffer them into the TLS layer.
        if self._appSendBuffer:
            self._unbufferPendingWrites()

        # Since the handshake is complete, the wire-level bytes we just
        # processed might turn into some application-level bytes; try to pull
        # those out.
        self._flushReceiveBuffers()


    def _shutdownTLS(self):
        """
        Initiate, or reply to, the shutdown handshake of the TLS layer. May
        be called multiple times until shutdown has completed.
        """
        try:
            self._tlsConnection.shutdown()
        except pep543.WantReadError:
            # We're waiting for more data from the remote peer.
            shutdownSuccess = False
        except pep543.Error:
            # Some other error was encountered. We're not going to try to
            # shutdown again: let's just say that we're screwed.
            self._tlsShutdownFinished(Failure())
            return
        else:
            shutdownSuccess = True

        self._flushSendBuffers()
        if shutdownSuccess:
            # Both sides have shutdown, so we can start closing lower-level
            # transport.
            self.transport.loseConnection()


    def _tlsShutdownFinished(self, reason):
        """
        Called when TLS connection has gone away; tell underlying transport to
        disconnect.

        @param reason: a L{Failure} whose value is an L{Exception} if we want to
            report that failure through to the wrapped protocol's
            C{connectionLost}, or L{None} if the C{reason} that
            C{connectionLost} should receive should be coming from the
            underlying transport.
        @type reason: L{Failure} or L{None}
        """
        if self._reason is None:
            self._reason = reason
        self._lostTLSConnection = True

        # We may need to send a TLS alert regarding the nature of the shutdown
        # here (for example, why a handshake failed), so always flush our send
        # buffer before telling our lower-level transport to go away.
        self._flushSendBuffers()
        # Using loseConnection causes the application protocol's
        # connectionLost method to be invoked non-reentrantly, which is always
        # a nice feature. However, for error cases (reason != None) we might
        # want to use abortConnection when it becomes available. The
        # loseConnection call is basically tested by test_handshakeFailure.
        # At least one side will need to do it or the test never finishes.
        self.transport.loseConnection()


    def connectionLost(self, reason):
        """
        Handle the possible repetition of calls to this method (due to either
        the underlying transport going away or due to an error at the TLS
        layer) and make sure the base implementation only gets invoked once.
        """
        if not self._lostTLSConnection:
            # Tell the TLS connection that it's not going to get any more data
            # and give it a chance to finish reading.
            try:
                self._tlsConnection.shutdown()
            except pep543.Error:
                # If we hit an error here we don't care.
                pass

            self._flushReceiveBuffers()
            self._lostTLSConnection = True
        reason = self._reason or reason
        self._reason = None
        self.connected = False
        ProtocolWrapper.connectionLost(self, reason)


    def loseConnection(self):
        """
        Send a TLS close alert and close the underlying connection.
        """
        if self.disconnecting:
            return
        # If connection setup has not finished, we don't really want to wait
        # for the handshake to complete unless the user has already tried to
        # send some data. In that case, we just tear the TCP conn down.
        if not self._handshakeDone and not self._appSendBuffer:
            self.abortConnection()
        self.disconnecting = True

        # Otherwise, we only shutdown if we don't have anything left to send.
        # If we do, we wait for that to happen.
        if not self._appSendBuffer and self._producer is None:
            self._shutdownTLS()


    def abortConnection(self):
        """
        Tear down TLS state so that if the connection is aborted mid-handshake
        we don't deliver any further data from the application.
        """
        self._aborted = True
        self.disconnecting = True
        self._shutdownTLS()
        self.transport.abortConnection()


    def write(self, data):
        """
        Process the given application bytes and send any resulting TLS traffic
        which arrives in the send BIO.

        If loseConnection was called, subsequent calls to write will
        drop the bytes on the floor.
        """
        # Writes after loseConnection are not supported, unless a producer has
        # been registered, in which case writes can happen until the producer
        # is unregistered:
        if self.disconnecting and self._producer is None:
            return
        self._write(data)


    def _bufferedWrite(self, data):
        """
        Put the given data into _appSendBuffer, and tell any listening
        producer that it should pause because we are now buffering.
        """
        self._appSendBuffer.append(data)
        if self._producer is not None:
            self._producer.pauseProducing()


    def _unbufferPendingWrites(self):
        """
        Un-buffer all waiting writes in _appSendBuffer.
        """
        pendingWrites, self._appSendBuffer = self._appSendBuffer, []
        for eachWrite in pendingWrites:
            self._write(eachWrite)

        if self._appSendBuffer:
            # If the TLS impementation ran out of buffer space on our way
            # through the loop earlier and re-buffered any of our outgoing
            # writes, then we're done; don't consider any future work.
            return

        if self._producer is not None:
            # If we have a registered producer, let it know that we have some
            # more buffer space.
            self._producer.resumeProducing()
            return

        if self.disconnecting:
            # Finally, if we have no further buffered data, no producer wants
            # to send us more data in the future, and the application told us
            # to end the stream, initiate a TLS shutdown.
            self._shutdownTLS()


    def _write(self, data):
        """
        Process the given application bytes and send any resulting TLS traffic
        which arrives in the send buffer.

        This may be called by dataReceived with bytes that were buffered before
        loseConnection was called, which is why this function doesn't check for
        disconnection but accepts the bytes regardless.
        """
        if self._lostTLSConnection:
            return

        # A TLS payload is 16kB max
        bufferSize = 2 ** 14

        # How far into the input we've gotten so far
        alreadySent = 0

        while alreadySent < len(data):
            toSend = data[alreadySent:alreadySent + bufferSize]
            try:
                sent = self._tlsConnection.write(toSend)
            except pep543.WantReadError:
                self._bufferedWrite(data[alreadySent:])
                break
            except pep543.TLSError:
                # Pretend TLS connection disconnected, which will trigger
                # disconnect of underlying transport. The error will be passed
                # to the application protocol's connectionLost method.
                self._tlsShutdownFinished(Failure())
                break
            else:
                alreadySent += sent
                self._flushSendBuffers()


    def writeSequence(self, iovec):
        """
        Write a sequence of application bytes by joining them into one string
        and passing them to write.
        """
        self.write(b"".join(iovec))


    def registerProducer(self, producer, streaming):
        # If we've already disconnected, nothing to do here:
        if self._lostTLSConnection:
            producer.stopProducing()
            return

        if not streaming:
            raise ValueError("Only streaming produces are supported")
        producer = _ProducerMembrane(producer)
        # This will raise an exception if a producer is already registered:
        self.transport.registerProducer(producer, True)
        self._producer = producer


    def unregisterProducer(self):
        # If we received a non-streaming producer, we need to stop the
        # streaming wrapper:
        self._producer = None
        self._producerPaused = False
        self.transport.unregisterProducer()
        if self.disconnecting and not self._appSendBuffer:
            self._shutdownTLS()


    # Support for INegotiated
    @property
    def negotiatedProtocol(self):
        protocolName = self._tlsConnection.negotiated_protocol

        if isinstance(protocolName, pep543.NextProtocol):
            protocolName = protocolName.value

        return protocolName
