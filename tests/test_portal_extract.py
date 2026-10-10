import json
import unittest
from architect.typed_schema import parse_schema
from architect.portal_extract import propose_fields, ModelResult

class FakeProvider:
    def __init__(self, reply, usage=None, error=None):
        self.reply=reply; self.usage=usage; self.error=error; self.calls=0; self.sent=None
    def __call__(self, source_text, unresolved):
        self.calls+=1
        self.sent={'source':source_text,'unresolved':unresolved}
        if self.error: raise RuntimeError(self.error)
        return {'content':self.reply,'usage':self.usage}

class PortalTests(unittest.TestCase):
    def specs(self, fields): return parse_schema(json.dumps(fields))

    def test_resolved_fields_never_sent(self):
        unresolved={}
        provider=FakeProvider(json.dumps({'values':{}}))
        result=propose_fields('page',unresolved,provider=provider,max_calls=1)
        self.assertEqual(provider.calls,0)
        self.assertEqual(result.candidates,{})

    def test_zero_calls_returns_nothing(self):
        unresolved=self.specs({'p':{'type':'number','selector':'jsonld:price'}})
        provider=FakeProvider('{}')
        result=propose_fields('price is 9.99',unresolved,provider=provider,max_calls=0)
        self.assertEqual(provider.calls,0); self.assertEqual(result.candidates,{})

    def test_hallucination_is_dropped(self):
        unresolved=self.specs({'p':{'type':'number','selector':'jsonld:price','hint':'the price'}})
        reply=json.dumps({'values':{'p':{'value':999,'excerpt':'a price'}}})
        result=propose_fields('the listed price is 9.99 dollars',unresolved,provider=FakeProvider(reply),max_calls=1)
        self.assertIsNone(result.candidates.get('p'))

    def test_verified_candidate_returned(self):
        unresolved=self.specs({'p':{'type':'number','selector':'jsonld:price','hint':'the price'}})
        reply=json.dumps({'values':{'p':{'value':9.99,'excerpt':'9.99 dollars'}}})
        result=propose_fields('the listed price is 9.99 dollars',unresolved,provider=FakeProvider(reply),max_calls=1)
        self.assertEqual(result.candidates['p']['value'],9.99)
        self.assertEqual(result.candidates['p']['excerpt'],'9.99 dollars')

    def test_provider_outage_fails_closed(self):
        unresolved=self.specs({'p':{'type':'string','selector':'text','hint':'author'}})
        result=propose_fields('by Alice',unresolved,provider=FakeProvider(None,error='boom'),max_calls=1)
        self.assertEqual(result.candidates,{})
        self.assertEqual(result.error,'provider failure: RuntimeError')

    def test_malformed_json_and_unknown_keys_dropped(self):
        unresolved=self.specs({'p':{'type':'string','selector':'text','hint':'author'}})
        for reply in ('not json','{"values":[]}','{"values":{"zzz":{"value":"x","excerpt":"x"}}}',
                      '{"values":{"p":{"value":"x","noexcerpt":1}}}','{"values":{"p":{"value":"x","excerpt":"nope"}}}',
                      '{"values":{"p":{"value":123,"excerpt":"123"}}}'):
            result=propose_fields('by Alice',unresolved,provider=FakeProvider(reply),max_calls=1)
            self.assertIsNone(result.candidates.get('p'),reply)

    def test_usage_missing_means_unknown_cost(self):
        unresolved=self.specs({'p':{'type':'string','selector':'text','hint':'author'}})
        reply=json.dumps({'values':{'p':{'value':'Alice','excerpt':'Alice'}}})
        result=propose_fields('by Alice',unresolved,provider=FakeProvider(reply,usage=None),max_calls=1)
        self.assertIsNone(result.cost_usd)
        self.assertIsNotNone(result.usage)

    def test_input_is_bounded(self):
        unresolved=self.specs({'p':{'type':'string','selector':'text','hint':'x'}})
        provider=FakeProvider('{"values":{}}')
        propose_fields('z'*100000,unresolved,provider=provider,max_calls=1,max_input_chars=100)
        self.assertLessEqual(len(provider.sent['source']),100)

    def test_one_call_max(self):
        unresolved=self.specs({'p':{'type':'string','selector':'text'},'q':{'type':'string','selector':'text'}})
        provider=FakeProvider('{"values":{}}')
        propose_fields('page text',unresolved,provider=provider,max_calls=1)
        self.assertEqual(provider.calls,1)
