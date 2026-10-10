"""Exercise the real bounded read/decompress transport without network access."""
import gzip
import unittest
from unittest.mock import patch
from architect.http import MAX_BYTES
from architect.safe_fetch import _transport, _PinnedHTTP, _PinnedHTTPS, AccessDenied

class FakeResponse:
    status=200
    def __init__(self, body, headers):
        self.body=body
        self.headers=headers
        self.read_args=[]
    def read(self, n):
        self.read_args.append(n)
        return self.body[:n]
    def getheaders(self): return list(self.headers.items())

class FakeConnection:
    instances=[]
    response=FakeResponse(b'',{})
    def __init__(self,host,port,ip,timeout):
        self.args=(host,port,ip,timeout)
        self.requests=[]
        self.closed=False
        self.instances.append(self)
    def request(self,*args,**kwargs): self.requests.append((args,kwargs))
    def getresponse(self): return self.response
    def close(self): self.closed=True

class TransportTests(unittest.TestCase):
    def transport(self,body,headers=None):
        FakeConnection.response=FakeResponse(body,headers or {'content-type':'text/html'})
        with patch('architect.safe_fetch._PinnedHTTP',FakeConnection):
            result=_transport('http://example.org/page','93.184.215.14',2)
        self.assertEqual(FakeConnection.instances[-1].args,
                         ('example.org',80,'93.184.215.14',2))
        self.assertEqual(FakeConnection.response.read_args,[MAX_BYTES+1])
        self.assertTrue(FakeConnection.instances[-1].closed)
        return result

    def test_bounded_read_and_pinned_request(self):
        result=self.transport(b'hello')
        self.assertEqual(result.body,b'hello')
        args,kwargs=FakeConnection.instances[-1].requests[0]
        self.assertEqual(args[:2],('GET','/page'))
        self.assertEqual(kwargs['headers']['Host'],'example.org')

    def test_oversized_response_refused_and_closed(self):
        with self.assertRaisesRegex(AccessDenied,'response too large'):
            self.transport(b'X'*(MAX_BYTES+2))
        self.assertTrue(FakeConnection.instances[-1].closed)
        self.assertEqual(FakeConnection.response.read_args,[MAX_BYTES+1])

    def test_gzip_bomb_refused_and_closed(self):
        with self.assertRaisesRegex(AccessDenied,'decompressed response too large'):
            self.transport(gzip.compress(b'Y'*(MAX_BYTES+2)),
                           {'content-encoding':'gzip','content-type':'text/html'})
        self.assertTrue(FakeConnection.instances[-1].closed)

    def test_pinned_http_connect_uses_validated_ip_not_hostname(self):
        with patch('architect.safe_fetch.socket.create_connection',return_value=object()) as connect:
            conn=_PinnedHTTP('example.org',80,'93.184.215.14',2)
            conn.connect()
            connect.assert_called_once_with(('93.184.215.14',80),2)

    def test_pinned_https_preserves_tls_hostname(self):
        from unittest.mock import Mock
        raw=Mock()
        with patch('architect.safe_fetch.socket.create_connection',return_value=raw) as connect:
            conn=_PinnedHTTPS('example.org',443,'93.184.215.14',2)
            wrapped=Mock()
            context=Mock(wrap_socket=Mock(return_value=wrapped))
            setattr(conn,'_context',context)
            conn.connect()
            connect.assert_called_once_with(('93.184.215.14',443),2)
            context.wrap_socket.assert_called_once_with(raw,server_hostname='example.org')
            self.assertIs(conn.sock,wrapped)

if __name__=='__main__': unittest.main()
