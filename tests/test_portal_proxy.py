import json
import unittest
from unittest.mock import patch
from architect.portal_extract import portal_provider, propose_fields
from architect.typed_schema import parse_schema


class MockResponse:
    def __init__(self, body, status=200):
        self.body=json.dumps(body).encode(); self.status=status
    def __enter__(self): return self
    def __exit__(self,*args): return False
    def read(self,n=-1): return self.body[:n]


class ProxyTests(unittest.TestCase):
    def test_local_proxy_request_is_bounded_and_has_no_tools(self):
        captured=[]
        def opener(request, timeout):
            self.assertEqual(timeout,20)
            self.assertEqual(request.full_url,'http://127.0.0.1:8901/v1/chat/completions')
            payload=json.loads(request.data)
            captured.append(payload)
            return MockResponse({'model':'deepseek/deepseek-v4.1-flash', 'choices':[{'message':{'content':'{"values":{}}'}}], 'usage':{'prompt_tokens':10,'completion_tokens':5,'cost':0.00002}})
        result=portal_provider('author Alice',{'author':parse_schema('{"author":{"type":"string"}}')['author']},opener=opener)
        self.assertEqual(result['model'],'deepseek/deepseek-v4.1-flash')
        self.assertEqual(captured[0]['max_tokens'],512)
        self.assertNotIn('tools',captured[0])
        self.assertNotIn('api_key',json.dumps(captured))
        self.assertNotIn('sk-',json.dumps(captured))
        self.assertIn('untrusted',captured[0]['messages'][0]['content'].lower())

    def test_proxy_url_not_user_configurable(self):
        with patch.dict('os.environ',{'ARCHITECT_NOUS_PROXY_URL':'http://evil.example/v1'}):
            with self.assertRaises(ValueError): portal_provider('x',{},opener=lambda *a,**kw:None)

    def test_reported_usage_cost_is_labeled(self):
        fields=parse_schema('{"author":{"type":"string"}}')
        def provider(source,unresolved):
            return {'content':'{"values":{"author":{"value":"Alice","excerpt":"Alice"}}}',
                    'usage':{'prompt_tokens':10,'completion_tokens':8,'cost':0.000032},'model':'deepseek/deepseek-v4.1-flash'}
        result=propose_fields('Alice',fields,provider=provider,max_calls=1)
        self.assertEqual(result.cost_usd,0.000032)
        self.assertEqual(result.cost_source,'provider_reported')
        self.assertEqual(result.model,'deepseek/deepseek-v4.1-flash')

    def test_budget_zero_stops_without_io(self):
        fields=parse_schema('{"author":{"type":"string"}}')
        def provider(*args): self.fail('called')
        r=propose_fields('Alice',fields,provider=provider,max_calls=1,max_output_tokens=0)
        self.assertEqual(r.calls,0)
        self.assertIn('budget',r.error)
