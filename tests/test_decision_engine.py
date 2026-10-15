import asyncio
import copy
import unittest
from dataclasses import replace
from architect.decision_engine import DecisionEngine
from architect.decision_types import DecisionPolicy, Provenance, ProviderResult
from test_decision_types import response, QUESTIONS

class SyntheticProvider:
    identity='test-only'
    def __init__(self, value=None): self.calls=[];self.value=value
    async def ask(self, body):
        self.calls.append(copy.deepcopy(body))
        return ProviderResult(copy.deepcopy(self.value if self.value is not None else response()),'req_test')

def provenance(allowed=True, candidates=()):
    return Provenance('https://example.org/','https://example.org/','a'*64,allowed,candidates)

class EngineTests(unittest.TestCase):
    def test_receipt_and_attempt_limit(self):
        provider=SyntheticProvider();engine=DecisionEngine(provider,DecisionPolicy())
        for _ in range(5):
            result=engine.evaluate({'text':'public'},QUESTIONS,provenance()).to_dict()
            self.assertEqual(result['outcome'],'ok')
            self.assertEqual(result['provider'],'test-only')
            self.assertEqual(result['usage']['input_tokens'],100)
        self.assertEqual(engine.evaluate({},QUESTIONS,provenance()).to_dict()['outcome'],'budget_exhausted')
        self.assertEqual(len(provider.calls),5)

    def test_denied_and_request_limits_zero_provider_calls(self):
        provider=SyntheticProvider();engine=DecisionEngine(provider,DecisionPolicy())
        cases=[({},QUESTIONS,provenance(False)),({'text':'x'*17000},QUESTIONS,provenance()),
               ({},{str(i):QUESTIONS['useful'] for i in range(9)},provenance()),
               ({},QUESTIONS,provenance(candidates=tuple({'id':str(i)} for i in range(13))))]
        for state,questions,prov in cases:
            self.assertIn(engine.evaluate(state,questions,prov).to_dict()['outcome'],('denied','budget_exhausted'))
        self.assertEqual(provider.calls,[])

    def test_invalid_usage_stops_subsequent_calls(self):
        bad=response();bad.pop('usage');p=SyntheticProvider(bad);e=DecisionEngine(p,DecisionPolicy())
        self.assertEqual(e.evaluate({},QUESTIONS,provenance()).to_dict()['outcome'],'invalid_response')
        self.assertEqual(e.evaluate({},QUESTIONS,provenance()).to_dict()['outcome'],'budget_exhausted')
        self.assertEqual(len(p.calls),1)

    def test_timeout_cancels_without_retry(self):
        cancelled=[]
        class Slow:
            identity='test-only'
            async def ask(self,body):
                try: await asyncio.sleep(10)
                finally:cancelled.append(1)
        e=DecisionEngine(Slow(),DecisionPolicy(deadline_s=0.02))
        self.assertEqual(e.evaluate({},QUESTIONS,provenance()).to_dict()['outcome'],'timeout')
        self.assertEqual(cancelled,[1])

    def test_unknown_choice_is_abstention_and_does_not_leak_extras(self):
        bad=response();bad['answers']['purpose'].update(choice='unknown',probabilities={'docs':0.1,'unknown':0.9})
        bad['secret']='TEST_ONLY_PRIVATE_MARKER'
        r=DecisionEngine(SyntheticProvider(bad),DecisionPolicy()).evaluate({},QUESTIONS,provenance()).to_dict()
        self.assertEqual(r['outcome'],'abstained')
        self.assertNotIn('TEST_ONLY_PRIVATE_MARKER',str(r))

    def test_option_order_reaches_provider_and_changes_cache_identity(self):
        import tempfile
        from pathlib import Path
        from architect.decision_cache import DecisionCache
        with tempfile.TemporaryDirectory() as tmp:
            p=SyntheticProvider();e=DecisionEngine(p,DecisionPolicy(),DecisionCache(Path(tmp)/'cache'))
            original=copy.deepcopy(QUESTIONS)
            original['purpose']['criteria']={'unknown':'Not enough evidence','docs':'SDK documentation'}
            reverse=copy.deepcopy(original)
            reverse['purpose']['criteria']=dict(reversed(list(original['purpose']['criteria'].items())))
            e.evaluate({},original,provenance())
            e.evaluate({},reverse,provenance())
            self.assertEqual(len(p.calls),2)
            self.assertEqual(list(p.calls[0]['questions']['purpose']['criteria']),['unknown','docs'])
            self.assertEqual(list(p.calls[1]['questions']['purpose']['criteria']),['docs','unknown'])

    def test_cost_reservation_refuses_before_call(self):
        p=SyntheticProvider();e=DecisionEngine(p,DecisionPolicy(estimated_budget_usd='0.000000001'))
        self.assertEqual(e.evaluate({},QUESTIONS,provenance()).to_dict()['outcome'],'budget_exhausted')
        self.assertEqual(p.calls,[])
