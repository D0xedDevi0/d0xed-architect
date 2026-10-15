"""SDK transport exercised without any real credentials."""
import asyncio
import importlib.util
import json
import logging
import os
import unittest
from unittest.mock import patch
from architect.decision_provider import JevProvider, ProviderUnavailable, ProviderFailure
from test_decision_types import response, QUESTIONS

SDK = importlib.util.find_spec('typesafe_sdk') is not None

class ProviderTests(unittest.IsolatedAsyncioTestCase):
    async def test_missing_key_unavailable(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ProviderUnavailable):
                await JevProvider().ask({'model':'jev-1.13.0','state':{},'questions':QUESTIONS})

    @unittest.skipUnless(SDK, 'optional SDK installed in isolated verification environment')
    async def test_actual_sdk_fixed_host_no_retries_and_request_id(self):
        import httpx2
        calls=[]
        async def handler(request):
            calls.append(request)
            self.assertEqual(str(request.url),'https://api.typesafe.ai/v1/systemone')
            self.assertEqual(json.loads(request.content)['model'],'jev-1.13.0')
            self.assertEqual(request.headers['authorization'],'Bearer TEST_ONLY_KEY')
            return httpx2.Response(200,json=response(),headers={'x-typesafe-request-id':'req_test'})
        with patch.dict(os.environ,{'TYPESAFE_BASE_URL':'https://evil.invalid','TYPESAFE_DEFAULT_MODEL':'wrong','TYPESAFE_LOG_LEVEL':'debug'}):
            out=await JevProvider('TEST_ONLY_KEY',transport=httpx2.MockTransport(handler)).ask(
                {'model':'jev-1.13.0','state':{},'questions':QUESTIONS})
        self.assertEqual(out.request_id,'req_test')
        self.assertEqual(len(calls),1)
        self.assertEqual(out.payload['model'],'jev-1.13.0')

    @unittest.skipUnless(SDK, 'optional SDK')
    async def test_redirect_and_rate_limit_never_retried(self):
        import httpx2
        for status in [307,429]:
            calls=[]
            async def handler(request):
                calls.append(request)
                return httpx2.Response(status,headers={'location':'https://evil.invalid','retry-after':'0'},json={})
            with self.assertRaises(ProviderFailure):
                await JevProvider('TEST_ONLY_KEY',transport=httpx2.MockTransport(handler)).ask(
                    {'model':'jev-1.13.0','state':{},'questions':QUESTIONS})
            self.assertEqual(len(calls),1)

    @unittest.skipUnless(SDK, 'optional SDK')
    async def test_logs_never_contain_body_or_key(self):
        import io
        import httpx2
        stream=io.StringIO()
        handler=logging.StreamHandler(stream)
        root=logging.getLogger()
        previous=root.level
        root.setLevel(logging.DEBUG);root.addHandler(handler)
        try:
            async def respond(request):
                self.assertIn(b'PUBLIC_SYNTHETIC_BODY_MARKER',request.content)
                return httpx2.Response(200,json=response())
            with patch.dict(os.environ,{'TYPESAFE_LOG_LEVEL':'debug'}):
                await JevProvider('TEST_ONLY_LOG_KEY',transport=httpx2.MockTransport(respond)).ask(
                    {'model':'jev-1.13.0','state':{'text':'PUBLIC_SYNTHETIC_BODY_MARKER'},'questions':QUESTIONS})
        finally:
            root.removeHandler(handler);root.setLevel(previous);handler.close()
        self.assertNotIn('PUBLIC_SYNTHETIC_BODY_MARKER',stream.getvalue())
        self.assertNotIn('TEST_ONLY_LOG_KEY',stream.getvalue())

    @unittest.skipUnless(SDK, 'optional SDK')
    async def test_hanging_transport_cancels(self):
        import httpx2
        cancelled=[]
        async def handler(request):
            try: await asyncio.sleep(20)
            finally: cancelled.append(True)
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(0.05):
                await JevProvider('TEST_ONLY_KEY',transport=httpx2.MockTransport(handler)).ask(
                    {'model':'jev-1.13.0','state':{},'questions':QUESTIONS})
        self.assertEqual(cancelled,[True])
