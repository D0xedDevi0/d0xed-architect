import unittest
from architect.http import Response
from architect.safe_fetch import fetch_public, AccessDenied, UnsafeURL


def response(url, code=200, body=b'<title>OK</title>', headers=None):
    return Response(url, code, headers or {}, body, 'text/html')


class SafeFetchTests(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        self.resolver=lambda host,port: ['93.184.215.14']
        def transport(url, ip, timeout):
            self.calls.append((url,ip))
            if url.endswith('/robots.txt'):
                return Response(url,200,{'content-type':'text/plain'},b'User-agent: *\nDisallow: /deny\nContent-Signal: ai-input=no\n','text/plain')
            return response(url)
        self.transport=transport

    def get(self, url):
        return fetch_public(url,resolver=self.resolver,transport=self.transport)

    def test_allowed_path_and_signal(self):
        result=self.get('https://example.org/ok')
        self.assertEqual(result.response.status,200)
        self.assertEqual(result.signals.get('ai-input'),'no')
        self.assertEqual([u for u,_ in self.calls], ['https://example.org/robots.txt','https://example.org/ok'])

    def test_denied_path_never_fetches_page(self):
        with self.assertRaises(AccessDenied): self.get('https://example.org/deny/private')
        self.assertEqual([u for u,_ in self.calls], ['https://example.org/robots.txt'])

    def test_unsafe_urls_never_connect(self):
        for u in ('file:///etc/passwd','https://127.0.0.1/x','https://localhost/x',
                  'https://user:pass@example.org/x','https://example.org:8080/x',
                  'https://169.254.169.254/latest/meta-data','http://[::1]/'):
            with self.subTest(u=u), self.assertRaises(UnsafeURL): self.get(u)
        self.assertEqual(self.calls,[])

    def test_private_dns_never_connects(self):
        for ip in ('127.0.0.1','10.2.3.4','192.168.1.1','172.16.0.1',
                   'fd00::1','fe80::1','::ffff:127.0.0.1'):
            self.resolver=lambda host,port,ip=ip:[ip]
            with self.subTest(ip=ip), self.assertRaises(UnsafeURL): self.get('https://example.org/a')
        self.assertEqual(self.calls,[])

    def test_redirect_to_private_host_is_refused(self):
        old=self.transport
        def transport(url,ip,timeout):
            if url.endswith('/start'): return response(url,302,b'',{'location':'http://127.0.0.1/private'})
            return old(url,ip,timeout)
        self.transport=transport
        with self.assertRaises(UnsafeURL): self.get('https://example.org/start')
        self.assertFalse(any('private' in u for u,_ in self.calls))

    def test_dns_rechecked_after_redirect(self):
        old=self.transport
        def transport(url,ip,timeout):
            if url.endswith('/start'): return response(url,302,b'',{'location':'https://second.org/a'})
            return old(url,ip,timeout)
        self.transport=transport
        self.resolver=lambda host,port:['127.0.0.1' if host=='second.org' else '93.184.215.14']
        with self.assertRaises(UnsafeURL): self.get('https://example.org/start')
        self.assertFalse(any('second.org' in u for u,_ in self.calls))

    def test_robots_server_error_fails_closed(self):
        self.transport=lambda url,ip,timeout:response(url,503) if url.endswith('/robots.txt') else self.fail('page fetched')
        with self.assertRaises(AccessDenied): self.get('https://example.org/ok')

    def test_robots_404_is_absent(self):
        self.transport=lambda url,ip,timeout:response(url,404) if url.endswith('/robots.txt') else response(url)
        self.assertEqual(self.get('https://example.org/ok').response.status,200)

    def test_402_does_not_pay(self):
        old=self.transport
        self.transport=lambda url,ip,timeout: response(url,402) if url.endswith('/pay') else old(url,ip,timeout)
        self.assertEqual(self.get('https://example.org/pay').response.status,402)

    def test_redirect_loop_refused(self):
        old=self.transport
        self.transport=lambda url,ip,timeout: response(url,302,b'',{'location':'/start'}) if url.endswith('/start') else old(url,ip,timeout)
        with self.assertRaises(UnsafeURL): self.get('https://example.org/start')

    def test_final_url_is_effective_url(self):
        old=self.transport
        def transport(url,ip,timeout):
            if url.endswith('/start'):
                return response(url,302,b'',{'location':'/final'})
            return old(url,ip,timeout)
        self.transport=transport
        self.assertEqual(self.get('https://example.org/start').response.url,'https://example.org/final')

    def test_redirect_fragment_is_not_sent(self):
        old=self.transport
        self.transport=lambda url,ip,timeout:response(url,302,b'',{'location':'/final#section'}) if url.endswith('/start') else old(url,ip,timeout)
        self.assertEqual(self.get('https://example.org/start').response.url,'https://example.org/final')
        self.assertTrue(any(u.endswith('/final') for u,_ in self.calls))

    def test_html_error_page_as_robots_fails_closed(self):
        old=self.transport
        self.transport=lambda url,ip,timeout:response(url,200,b'<html>error</html>',{'content-type':'text/html'}) if url.endswith('/robots.txt') else old(url,ip,timeout)
        with self.assertRaises(AccessDenied): self.get('https://example.org/ok')
        self.assertFalse(any(u.endswith('/ok') for u,_ in self.calls))

    def test_excessive_crawl_delay_fails_without_sleeping(self):
        old=self.transport
        self.transport=lambda url,ip,timeout:Response(url,200,{'content-type':'text/plain'},b'User-agent: *\nCrawl-delay: 99999999\n','text/plain') if url.endswith('/robots.txt') else old(url,ip,timeout)
        from unittest.mock import patch
        with patch('architect.safe_fetch.time.sleep') as sleep:
            with self.assertRaises(AccessDenied): self.get('https://example.org/ok')
            sleep.assert_not_called()

    def test_one_page_requires_no_crawl_delay_sleep(self):
        old=self.transport
        self.transport=lambda url,ip,timeout:Response(url,200,{'content-type':'text/plain'},b'User-agent: *\nCrawl-delay: 2\n','text/plain') if url.endswith('/robots.txt') else old(url,ip,timeout)
        from unittest.mock import patch
        with patch('architect.safe_fetch.time.sleep') as sleep:
            self.assertEqual(self.get('https://example.org/ok').response.status,200)
            sleep.assert_not_called()
