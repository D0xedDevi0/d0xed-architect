import json
import unittest
from architect.http import Response
from architect.safe_fetch import AccessResult, AccessDenied
from architect.typed import extract_typed
from architect import mcp_server


def resp(url, code=200, body=b'<html><head><title>T</title><meta name="description" content="d"></head><body><h1>H</h1>price 9.99</body></html>', headers=None, ctype='text/html'):
    return Response(url, code, headers or {}, body, ctype)

def allowed_fetcher(transport):
    def f(url, **kw):
        return AccessResult(transport(url,'1.1.1.1',15), {'ai-input':'allow'})
    return f

class IntegrationTests(unittest.TestCase):
    def schema(self): return json.dumps({'title':{'type':'string','selector':'title'},
        'price':{'type':'number','selector':'jsonld:price','hint':'the price'}})

    def model_schema(self): return json.dumps({'title':{'type':'string','selector':'title'},
        'price':{'type':'number','hint':'the price'}})

    def test_allowed_deterministic(self):
        fetcher=lambda url,**kw: AccessResult(resp(url), {})
        out=extract_typed('https://e.org/x',self.schema(),fetcher=fetcher)
        self.assertEqual(out['status'],200)
        self.assertEqual(out['values']['title'],'T')
        self.assertEqual(out['fields']['title']['method'],'deterministic')
        self.assertIn('source_sha256',out['fields']['title'])

    def test_denied_no_page_no_model(self):
        def fetcher(url,**kw): raise AccessDenied('disallowed')
        calls=[]
        out=extract_typed('https://e.org/x',self.schema(),use_llm=True,fetcher=fetcher,model=lambda s,u:(calls.append(1) or {}))
        self.assertNotEqual(out['status'],200)
        self.assertEqual(calls,[])

    def test_explicit_selector_not_filled_from_unrelated_text(self):
        html=b'<html><head><title>T</title></head><body>price 9.99 but no JSON-LD</body></html>'
        calls=[]
        schema=json.dumps({'price':{'type':'number','selector':'jsonld:price','hint':'price'}})
        out=extract_typed('https://e.org/x',schema,use_llm=True,
                          fetcher=lambda u,**kw:AccessResult(resp(u,body=html),{}),
                          model=lambda s,u:(calls.append(1) or {'content':'{"values":{}}'}))
        self.assertIsNone(out['values']['price'])
        self.assertEqual(calls,[])

    def test_model_fills_unresolved_only(self):
        html=b'<title>T</title> price is 9.99 dollars'
        def fetcher(url,**kw): return AccessResult(resp(url,body=html), {})
        def model(source,unresolved):
            self.assertNotIn('title',unresolved); self.assertIn('price',unresolved)
            return {'content':json.dumps({'values':{'price':{'value':9.99,'excerpt':'9.99 dollars'}}}),'usage':{}}
        out=extract_typed('https://e.org/x',self.model_schema(),use_llm=True,fetcher=fetcher,model=model)
        self.assertEqual(out['values']['price'],9.99)
        self.assertEqual(out['fields']['price']['method'],'llm_verified')
        self.assertEqual(out['fields']['price']['source_excerpt'],'9.99 dollars')
        self.assertIsInstance(out['fields']['price']['locator'],str)
        self.assertIn('9.99 dollars',html.decode())
        self.assertEqual(out['url'],'https://e.org/x')

    def test_hallucination_dropped(self):
        def fetcher(url,**kw): return AccessResult(resp(url,body=b'<title>T</title> no prices here'), {})
        def model(source,unresolved):
            return {'content':json.dumps({'values':{'price':{'value':123,'excerpt':'fabricated'}}}),'usage':{}}
        out=extract_typed('https://e.org/x',self.model_schema(),use_llm=True,fetcher=fetcher,model=model)
        self.assertIsNone(out['values']['price'])

    def test_provider_outage_partial(self):
        def fetcher(url,**kw): return AccessResult(resp(url), {})
        def model(source,unresolved): raise RuntimeError('down')
        out=extract_typed('https://e.org/x',self.model_schema(),use_llm=True,fetcher=fetcher,model=model)
        self.assertEqual(out['values']['title'],'T')
        self.assertIsNone(out['values']['price'])
        self.assertIn('provider failure: RuntimeError',out['llm'].get('error',''))

    def test_ai_input_no_suppresses_model(self):
        def fetcher(url,**kw): return AccessResult(resp(url), {'ai-input':'no'})
        calls=[]
        out=extract_typed('https://e.org/x',self.schema(),use_llm=True,fetcher=fetcher,model=lambda s,u:(calls.append(1) or {}))
        self.assertEqual(calls,[])

    def test_non200_no_model(self):
        def fetcher(url,**kw): return AccessResult(resp(url,code=404), {})
        calls=[]
        out=extract_typed('https://e.org/x',self.schema(),use_llm=True,fetcher=fetcher,model=lambda s,u:(calls.append(1) or {}))
        self.assertEqual(out['status'],'http_404'); self.assertEqual(calls,[])

    def test_invalid_schema_raises(self):
        with self.assertRaises(ValueError):
            extract_typed('https://e.org/x','{',fetcher=lambda url,**kw:AccessResult(resp(url),{}))

    def test_required_missing_is_reported(self):
        schema=json.dumps({'price':{'type':'number','selector':'jsonld:price','required':True}})
        out=extract_typed('https://e.org/x',schema,fetcher=lambda u,**kw:AccessResult(resp(u),{}))
        self.assertIsNone(out['values']['price'])
        self.assertEqual(out['validation_errors']['price'],'required field missing')

    def test_402_no_model_no_payment(self):
        calls=[]
        out=extract_typed('https://e.org/pay',self.schema(),use_llm=True,
                          fetcher=lambda u,**kw:AccessResult(resp(u,code=402),{}),
                          model=lambda s,u:(calls.append(1) or {}))
        self.assertEqual(out['status'],'payment_required')
        self.assertEqual(calls,[])
        self.assertIsNone(out['values']['price'])

    def test_model_call_limit_is_explicit(self):
        with self.assertRaises(ValueError):
            extract_typed('https://e.org/x',self.schema(),max_model_calls=2)

    def test_mcp_registers_extract_typed(self):
        names={i.name for i in mcp_server.srv._tool_manager.list_tools()}
        self.assertIn('extract_typed',names)
        self.assertIn('scrape_url',names)


if __name__=='__main__':
    unittest.main()
