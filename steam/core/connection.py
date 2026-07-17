import logging
import struct

import gevent
from gevent import event
from gevent import queue
from gevent import socket
from gevent.select import select as gselect

logger = logging.getLogger("Connection")


class Connection:
    MAGIC = b'VT01'
    FMT = '<I4s'
    FMT_SIZE = struct.calcsize(FMT)

    def __init__(self):
        self.socket = None
        self.connected = False
        self.server_addr = None

        self._reader = None
        self._writer = None
        self._readbuf = b''
        self.send_queue = queue.Queue()
        self.recv_queue = queue.Queue()

        self.event_connected = event.Event()

    @property
    def local_address(self):
        return self.socket.getsockname()[0]

    def connect(self, server_addr):
        self._new_socket()

        logger.debug("Attempting connection to %s", str(server_addr))

        try:
            self._connect(server_addr)
        except socket.error:
            return False

        self.server_addr = server_addr
        self.recv_queue.queue.clear()

        self._reader = gevent.spawn(self._reader_loop)
        self._writer = gevent.spawn(self._writer_loop)

        logger.debug("Connected.")
        self.event_connected.set()
        return True

    def disconnect(self):
        if not self.event_connected.is_set():
            return
        self.event_connected.clear()

        self.server_addr = None

        if self._reader:
            self._reader.kill(block=False)
            self._reader = None
        if self._writer:
            self._writer.kill(block=False)
            self._writer = None

        self._readbuf = b''
        self.send_queue.queue.clear()
        self.recv_queue.queue.clear()
        self.recv_queue.put(StopIteration)

        self._close_socket()

        logger.debug("Disconnected.")

    def _frame(self, message):
        """Wrap an outgoing message for the wire. Overridable per transport."""
        return struct.pack(Connection.FMT, len(message), Connection.MAGIC) + message

    def _close_socket(self):
        """Tear down the underlying socket. Overridable per transport."""
        self.socket.close()

    def __iter__(self):
        return self.recv_queue

    def put_message(self, message):
        self.send_queue.put(message)

    def _writer_loop(self):
        while True:
            message = self.send_queue.get()
            packet = self._frame(message)
            try:
                self._write_data(packet)
            except:
                logger.debug("Connection error (writer).")
                self.disconnect()
                return

    def _reader_loop(self):
        while True:
            rlist, _, _ = gselect([self.socket], [], [])

            if self.socket in rlist:
                data = self._read_data()

                if not data:
                    logger.debug("Connection error (reader).")
                    self.disconnect()
                    return

                self._readbuf += data
                self._read_packets()

    def _read_packets(self):
        header_size = Connection.FMT_SIZE
        buf = self._readbuf

        while len(buf) > header_size:
            message_length, magic = struct.unpack_from(Connection.FMT, buf)

            if magic != Connection.MAGIC:
                logger.debug("invalid magic, got %s" % repr(magic))
                self.disconnect()
                return

            packet_length = header_size + message_length

            if len(buf) < packet_length:
                return

            message = buf[header_size:packet_length]
            buf = buf[packet_length:]

            self.recv_queue.put(message)

        self._readbuf = buf


class TCPConnection(Connection):
    def _new_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def _connect(self, server_addr):
        self.socket.connect(server_addr)

    def _read_data(self):
        try:
            return self.socket.recv(16384)
        except socket.error:
            return ''

    def _write_data(self, data):
        self.socket.sendall(data)


class UDPConnection(Connection):
    def _new_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _connect(self, server_addr):
        pass

    def _read_data(self):
        pass

    def _write_data(self, data):
        pass


class WebsocketConnection(Connection):
    """CM connection over a secure WebSocket (``wss://<host>:<port>/cmsocket/``).

    Steam's modern ``IAuthenticationService`` credential flow is only served over the
    WebSocket CM endpoints, not the raw TCP ones. This transport differs from
    :class:`TCPConnection` in two ways:

    * **Framing** -- each Steam message is a single binary WebSocket frame. There is no
      ``VT01`` magic + length prefix (the WebSocket layer already delimits messages).
    * **Encryption** -- TLS secures the channel, so there is no Steam AES
      ``ChannelEncrypt`` handshake and messages are sent as-is.

    .. note::
        ``recv()`` blocks the reader greenlet. Outside a fully gevent application call
        :meth:`steam.monkey.patch_minimal` first so the underlying socket cooperates.
    """

    CONNECT_TIMEOUT = 15  #: seconds to wait for the WebSocket handshake

    def __init__(self):
        super().__init__()
        self.ws = None

    def connect(self, server_addr):
        import websocket  # lazy import: only the websocket transport needs it

        try:
            import gevent.monkey
            unpatched = [m for m in ('socket', 'ssl') if not gevent.monkey.is_module_patched(m)]
            if unpatched:
                logger.warning("Websocket transport needs cooperative %s; "
                               "call steam.monkey.patch_minimal() outside a gevent app",
                               ' and '.join(unpatched))
        except Exception:
            pass

        host, port = server_addr
        url = "wss://%s:%s/cmsocket/" % (host, port)
        logger.debug("Attempting websocket connection to %s", url)

        try:
            self.ws = websocket.create_connection(url, timeout=self.CONNECT_TIMEOUT,
                                                  enable_multithread=True)
        except Exception as exp:
            logger.debug("Websocket connection failed: %s", exp)
            return False

        self.ws.settimeout(None)  # block in the reader greenlet until a frame arrives
        self.socket = self.ws.sock  # exposes local_address / getsockname
        self.server_addr = server_addr
        self.recv_queue.queue.clear()

        self._reader = gevent.spawn(self._reader_loop)
        self._writer = gevent.spawn(self._writer_loop)

        logger.debug("Connected.")
        self.event_connected.set()
        return True

    def _frame(self, message):
        # A Steam message is one binary WebSocket frame -- no VT01 length prefix.
        return message

    def _write_data(self, data):
        self.ws.send_binary(data)

    def _close_socket(self):
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass
            self.ws = None

    def _reader_loop(self):
        import websocket  # for ABNF opcodes

        while True:
            try:
                opcode, data = self.ws.recv_data()  # auto-handles ping/pong internally
            except Exception as exp:
                logger.debug("Connection error (reader): %r", exp)
                self.disconnect()
                return

            if opcode == websocket.ABNF.OPCODE_BINARY:
                self.recv_queue.put(data)
            elif opcode == websocket.ABNF.OPCODE_CLOSE:
                code = int.from_bytes(data[:2], 'big') if len(data) >= 2 else None
                logger.debug("Websocket closed by peer: code=%s reason=%r", code, data[2:])
                self.disconnect()
                return
            # text frames are ignored -- the CM only sends binary
