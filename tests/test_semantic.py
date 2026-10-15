import hashlib
import unittest
from architect.http import Response
from architect.safe_fetch import AccessResult, AccessDenied, UnsafeURL
from architect.semantic import annotate_page, fetch_judgment_page
from architect.decision_engine import DecisionEngine
from architect.decision_types import DecisionPolicy, ProviderResult

class PageProvider:
    identity='test-only'
    def __init__(self): self.calls=[]
    async def ask(self,body):
        self.calls.append(body)
        answers={}
        for name,q in body['questions'].items():
            if q['type']=='choice':
                label=next(k for k in q['criteria'] if k not in ('none','unknown'))
                answers[name]={'type':'choice','choice':label,'confidence':1.0,
                    'probabilities':{k:float(k==label) for k in q['criteria']}}
            elif q['type']=='score':
                answers[name]={'type':'score','score':2.0,'confidence':1.0,
                    'legend':{str(i):v for i,v in enumerate(q['criteria'])},
                    'probabilities':{'0':0.0,'1':0.0,'2':1.0}}
            else:answers[name]={'type':'noul','noul':0.9}
        return ProviderResult({'model':body['model'],'answers':answers,
                              'usage':{'input_tokens':100,'output_tokens':20}})

def page(body=b'<title>SDK</title><p>Python SDK documentation.</p>',signals=None,status=200):
    return AccessResult(Response('https://example.org/page',status,{},body,'text/html'),
                        signals if signals is not None else {'ai-input':'yes'})

class SemanticTests(unittest.TestCase):
    def test_public_page_real_adapter_contract(self):
        p=PageProvider();out=annotate_page(page(),'Find SDK docs',DecisionEngine(p))
        self.assertEqual(out['decision']['outcome'],'ok')
        self.assertEqual(len(p.calls),1)
        self.assertEqual(out['source_sha256'],hashlib.sha256(page().response.body).hexdigest())
        for c in out['candidates']:
            self.assertEqual(page().response.body[c['byte_offset']:c['byte_offset']+len(c['excerpt'].encode())],c['excerpt'].encode())

    def test_denial_and_absent_permission_never_call_model(self):
        for obj,consent in [(page(signals={'ai-input':'no'}),True),(page(signals={}),False),
                            (page(status=402),True),(page(status=404),True)]:
            p=PageProvider();out=annotate_page(obj,'docs',DecisionEngine(p),operator_allows_model_input=consent)
            self.assertEqual(p.calls,[]);self.assertEqual(out['decision']['outcome'],'denied')
        p=PageProvider();out=annotate_page(page(signals={}), 'docs',DecisionEngine(p),operator_allows_model_input=True)
        self.assertEqual(len(p.calls),1)

    def test_hidden_nonliteral_and_private_spans_omitted(self):
        raw=b'<p hidden>HIDDEN_MARKER</p><p>A &amp; B</p><p>Contact bob@example.org</p><p>api_key=TEST_ONLY_PRIVATE_MARKER</p><p>Visible docs</p>'
        p=PageProvider();out=annotate_page(page(raw),'docs',DecisionEngine(p))
        sent=str(p.calls)
        for forbidden in ['HIDDEN_MARKER','A & B','bob@example.org','TEST_ONLY_PRIVATE_MARKER']:
            self.assertNotIn(forbidden,sent)
            self.assertNotIn(forbidden,str(out))
        self.assertGreaterEqual(out['omitted_candidates'],3)

    def test_candidates_capped_and_offline_no_provider(self):
        raw=b''.join(b'<p>Public paragraph '+str(i).encode()+b'</p>' for i in range(20))
        out=annotate_page(page(raw),'docs',None)
        self.assertEqual(len(out['candidates']),12)
        self.assertEqual(out['omitted_candidates'],8)
        self.assertEqual(out['decision']['outcome'],'unavailable')

    def test_substantive_objective_evidence_precedes_navigation(self):
        raw=(b''.join(b'<a>Navigation '+str(i).encode()+b'</a>' for i in range(20))+
             b'<p>Python SDK integration documentation: install the client and send typed questions to system_one using structured state.</p>')
        out=annotate_page(page(raw),'Python SDK integration',None)
        self.assertIn('Python SDK',out['candidates'][0]['excerpt'])

    def test_cross_origin_redirect_blocked_before_transport(self):
        calls=[]
        def transport(url,ip,timeout):
            calls.append(url)
            if url.endswith('/robots.txt'):return Response(url,404,{},b'','text/plain')
            return Response(url,302,{'location':'https://evil.example/secret'},b'','text/html')
        with self.assertRaises((AccessDenied,UnsafeURL,ValueError)):
            fetch_judgment_page('https://example.org/page',resolver=lambda h,p:['1.1.1.1'],transport=transport)
        self.assertEqual(calls,['https://example.org/robots.txt','https://example.org/page'])

    def test_robots_deny_private_dns_and_query_zero_page_hits(self):
        calls=[]
        def transport(url,ip,timeout):
            calls.append(url)
            return Response(url,200,{},b'User-agent: *\nDisallow: /blocked','text/plain')
        with self.assertRaises(AccessDenied):
            fetch_judgment_page('https://example.org/blocked',resolver=lambda h,p:['1.1.1.1'],transport=transport)
        self.assertEqual(calls,['https://example.org/robots.txt']);calls.clear()
        for url,resolver in [('https://example.org/page',lambda h,p:['127.0.0.1']),
                             ('https://example.org/?token=TEST_ONLY',lambda h,p:['1.1.1.1'])]:
            with self.assertRaises((UnsafeURL,ValueError)):
                fetch_judgment_page(url,resolver=resolver,transport=transport)
        self.assertEqual(calls,[])
