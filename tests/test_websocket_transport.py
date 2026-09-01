import unittest

import gevent
import websocket
from gevent.queue import Queue as GQueue
from mock import patch, MagicMock

from steam.core.cm import CMClient, CMServerList
from steam.core.connection import WebsocketConnection
from steam.core.msg import MsgProto
from steam.enums import ETransport
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

    def shutdown(self):
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
        client = CMClient(ETransport.WebSocket)
        self.assertIsInstance(client.connection, WebsocketConnection)
        self.assertEqual(client.cm_servers.transport, ETransport.WebSocket)

    def test_send_is_not_aes_encrypted(self):
        client = CMClient(ETransport.WebSocket)
        captured = []
        client.connection.put_message = lambda data: captured.append(data)

        msg = MsgProto(EMsg.ClientHeartBeat)
        client.send(msg)

        # No channel key is ever negotiated over wss, so the message goes out unencrypted.
        self.assertIsNone(client.channel_key)
        self.assertEqual(captured, [msg.serialize()])

    def test_connect_marks_channel_secured_without_handshake(self):
        client = CMClient(ETransport.WebSocket)
        client.cm_servers.merge_list([('cm.example.net', 27019)])
        client.connection.connect = MagicMock(return_value=True)

        secured = []
        client.on(client.EVENT_CHANNEL_SECURED, lambda: secured.append(True))

        self.assertTrue(client.connect(retry=1))
        self.addCleanup(client.disconnect)
        gevent.sleep(0.05)  # let the emitted channel_secured handler run

        self.assertTrue(client.channel_secured)
        self.assertEqual(secured, [True])


def cm_entry(endpoint, cmtype='websockets', realm='steamglobal', wtd_load='1.0'):
    return {'endpoint': endpoint, 'legacy_endpoint': endpoint, 'type': cmtype,
            'dc': 'fra1', 'realm': realm, 'load': '1', 'wtd_load': wtd_load}


class WebsocketBootstrapTest(unittest.TestCase):
    def test_bootstrap_uses_websocket_serverlist(self):
        sl = CMServerList()
        sl.transport = ETransport.WebSocket
        resp = {'response': {'serverlist': [
            cm_entry('192.0.2.4:27017', cmtype='netfilter'),
            cm_entry('cm-b.example.net:27019', wtd_load='5.0'),
            cm_entry('cm-a.example.net:443', wtd_load='0.5'),
            cm_entry('cm-china.example.net:443', realm='steamchina'),
        ]}}

        with patch('steam.webapi.get', return_value=resp) as get:
            self.assertTrue(sl.bootstrap_from_webapi())

        # GetCMListForConnect for the websocket transport
        self.assertEqual(get.call_args.args[:3], ('ISteamDirectory', 'GetCMListForConnect', 1))
        self.assertEqual(get.call_args.kwargs['params']['cmtype'], 'websockets')

        # only global-realm websocket CMs, least loaded first
        self.assertEqual(list(sl.list), [('cm-a.example.net', 443), ('cm-b.example.net', 27019)])

    def test_bootstrap_tcp_requests_netfilter(self):
        sl = CMServerList()
        sl.transport = ETransport.TCP
        resp = {'response': {'serverlist': [cm_entry('192.0.2.4:27017', cmtype='netfilter'),
                                            cm_entry('cm.example.net:443')]}}

        with patch('steam.webapi.get', return_value=resp) as get:
            self.assertTrue(sl.bootstrap_from_webapi())

        self.assertEqual(get.call_args.kwargs['params']['cmtype'], 'netfilter')
        self.assertEqual(list(sl.list), [('192.0.2.4', 27017)])

    def test_dns_bootstrap_disabled_for_websocket(self):
        sl = CMServerList()
        sl.transport = ETransport.WebSocket
        self.assertFalse(sl.bootstrap_from_dns())

    def test_bootstrap_without_matching_servers_returns_false(self):
        # A response with no websocket CMs must fail gracefully, not raise.
        sl = CMServerList()
        sl.transport = ETransport.WebSocket
        resp = {'response': {'serverlist': [cm_entry('192.0.2.4:27017', cmtype='netfilter')]}}

        with patch('steam.webapi.get', return_value=resp):
            self.assertFalse(sl.bootstrap_from_webapi())

        resp = {'response': {}}
        with patch('steam.webapi.get', return_value=resp):
            self.assertFalse(sl.bootstrap_from_webapi())


if __name__ == '__main__':
    unittest.main()
