import unittest

import gevent
import websocket
from gevent.queue import Queue as GQueue
from mock import patch, MagicMock

from steam.core.cm import CMClient, CMServerList
from steam.core.connection import WebsocketConnection
from steam.core.msg import MsgProto
from steam.enums.emsg import EMsg


class FakeWS:
    """Minimal stand-in for a websocket-client connection driven by gevent queues."""

    def __init__(self):
        self.sent = []
        self.closed = False
        self.sock = MagicMock()
        self._incoming = GQueue()

    def settimeout(self, _):
        # no-op: the fake is driven by gevent queues, so socket timeouts don't apply
        pass

    def send_binary(self, data):
        self.sent.append(data)

    def recv_data(self):
        # blocks cooperatively until fed / killed; frames are (opcode, data) tuples
        return self._incoming.get()

    def close(self):
        self.closed = True

    def feed(self, data):
        self._incoming.put((websocket.ABNF.OPCODE_BINARY, data))


class WebsocketConnectionTest(unittest.TestCase):
    def test_connect_builds_wss_url(self):
        fake = FakeWS()
        with patch('websocket.create_connection', return_value=fake) as cc:
            conn = WebsocketConnection()
            self.assertTrue(conn.connect(('cm.example.net', 27019)))
            self.addCleanup(conn.disconnect)

        self.assertEqual(cc.call_args[0][0], 'wss://cm.example.net:27019/cmsocket/')

    def test_outgoing_frame_has_no_vt01_framing(self):
        fake = FakeWS()
        with patch('websocket.create_connection', return_value=fake):
            conn = WebsocketConnection()
            conn.connect(('cm.example.net', 27019))
            self.addCleanup(conn.disconnect)

            conn.put_message(b'\x01\x02\x03')
            gevent.sleep(0.05)  # let the writer greenlet run

        # The raw message goes out verbatim -- no 'VT01' magic or length prefix.
        self.assertEqual(fake.sent, [b'\x01\x02\x03'])

    def test_incoming_frame_becomes_one_message(self):
        fake = FakeWS()
        with patch('websocket.create_connection', return_value=fake):
            conn = WebsocketConnection()
            conn.connect(('cm.example.net', 27019))
            self.addCleanup(conn.disconnect)

            fake.feed(b'HELLO')
            self.assertEqual(conn.recv_queue.get(timeout=1), b'HELLO')

    def test_disconnect_closes_socket(self):
        fake = FakeWS()
        with patch('websocket.create_connection', return_value=fake):
            conn = WebsocketConnection()
            conn.connect(('cm.example.net', 27019))
            conn.disconnect()

        self.assertTrue(fake.closed)


class WebsocketCMClientTest(unittest.TestCase):
    def test_protocol_selects_websocket_connection(self):
        client = CMClient(CMClient.PROTOCOL_WEBSOCKET)
        self.assertIsInstance(client.connection, WebsocketConnection)
        self.assertTrue(client.cm_servers.websocket)

    def test_send_is_not_aes_encrypted(self):
        client = CMClient(CMClient.PROTOCOL_WEBSOCKET)
        captured = []
        client.connection.put_message = lambda data: captured.append(data)

        msg = MsgProto(EMsg.ClientHeartBeat)
        client.send(msg)

        # No channel key is ever negotiated over wss, so the message goes out unencrypted.
        self.assertIsNone(client.channel_key)
        self.assertEqual(captured, [msg.serialize()])

    def test_connect_marks_channel_secured_without_handshake(self):
        client = CMClient(CMClient.PROTOCOL_WEBSOCKET)
        client.cm_servers.merge_list([('cm.example.net', 27019)])
        client.connection.connect = MagicMock(return_value=True)

        secured = []
        client.on(client.EVENT_CHANNEL_SECURED, lambda: secured.append(True))

        self.assertTrue(client.connect(retry=1))
        self.addCleanup(client.disconnect)
        gevent.sleep(0.05)  # let the emitted channel_secured handler run

        self.assertTrue(client.channel_secured)
        self.assertEqual(secured, [True])


class WebsocketBootstrapTest(unittest.TestCase):
    def test_bootstrap_uses_websocket_serverlist(self):
        sl = CMServerList()
        sl.websocket = True
        resp = {'response': {'result': 1,
                             'serverlist': ['192.0.2.4:27017'],
                             'serverlist_websockets': ['cm.example.net:27019']}}

        with patch('steam.webapi.get', return_value=resp):
            self.assertTrue(sl.bootstrap_from_webapi())

        self.assertIn(('cm.example.net', 27019), sl.list)
        self.assertNotIn(('192.0.2.4', 27017), sl.list)

    def test_dns_bootstrap_disabled_for_websocket(self):
        sl = CMServerList()
        sl.websocket = True
        self.assertFalse(sl.bootstrap_from_dns())


if __name__ == '__main__':
    unittest.main()
