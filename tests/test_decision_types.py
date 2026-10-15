"""Typed semantic boundary; all fixtures are synthetic, not real inference."""
import copy
import unittest
from architect.decision_types import validate_response, DecisionValidationError

QUESTIONS = {
    'purpose': {'type': 'choice', 'criteria': {'docs': 'SDK documentation', 'unknown': 'Not enough evidence'}},
    'relevance': {'type': 'score', 'criteria': ['unrelated', 'partial', 'direct']},
    'useful': {'type': 'noul', 'instructions': 'Is this useful?'}}

def response():
    return {'model': 'jev-1.13.0', 'answers': {
        'purpose': {'type': 'choice', 'choice': 'docs', 'confidence': 0.8,
                    'probabilities': {'docs': 0.9, 'unknown': 0.1}},
        'relevance': {'type': 'score', 'score': 1.9, 'confidence': 0.85,
                      'legend': {'0': 'unrelated', '1': 'partial', '2': 'direct'},
                      'probabilities': {'0': 0.0, '1': 0.1, '2': 0.9}},
        'useful': {'type': 'noul', 'noul': 0.9}},
        'usage': {'input_tokens': 100, 'output_tokens': 10}}

class ResponseTests(unittest.TestCase):
    def test_valid_choice_score_noul(self):
        value = response()
        self.assertEqual(validate_response(value, QUESTIONS, 'jev-1.13.0'), value)

    def test_response_rejects_invalid_contracts(self):
        cases = []
        for path, value in [
            (('model',), 'jev-latest'),
            (('usage','input_tokens'), True),
            (('usage','output_tokens'), -1),
            (('answers','purpose','choice'), 'invented'),
            (('answers','purpose','confidence'), 0.2),
            (('answers','purpose','probabilities','docs'), 0.2),
            (('answers','relevance','score'), 1.0),
            (('answers','relevance','legend','0'), 'changed'),
            (('answers','useful','noul'), float('nan')),
            (('answers','useful','noul'), True),
            (('answers','useful','noul'), 2)]:
            x=response(); dest=x
            for k in path[:-1]: dest=dest[k]
            dest[path[-1]]=value; cases.append(x)
        x=response(); x['answers']['extra']={};cases.append(x)
        x=response();del x['usage'];cases.append(x)
        for x in cases:
            with self.subTest(payload=x), self.assertRaises(DecisionValidationError):
                validate_response(x, QUESTIONS, 'jev-1.13.0')

    def test_policy_provenance_and_receipt_contract(self):
        from architect.decision_types import DecisionPolicy, Provenance, DecisionReceipt
        p=DecisionPolicy()
        self.assertEqual((p.model,p.max_attempts,p.max_body_bytes),('jev-1.13.0',5,16384))
        for kw in [{'max_attempts':6},{'deadline_s':11},{'max_body_bytes':20000},
                   {'model':'jev-latest'},{'estimated_budget_usd':'NaN'},{'max_questions':True}]:
            with self.subTest(kw=kw), self.assertRaises(ValueError): DecisionPolicy(**kw)
        source=Provenance('https://example.org/','https://example.org/','a'*64,True)
        self.assertEqual(source.to_dict()['source_sha256'],'a'*64)
        for u in ['http://127.0.0.1/','https://u:p@example.org/','https://e.org/?token=private']:
            with self.subTest(url=u), self.assertRaises(ValueError): Provenance(u,u,'a'*64,True)
        receipt=DecisionReceipt({'outcome':'ok','api_key':'TEST_ONLY_PRIVATE_MARKER'})
        self.assertNotIn('api_key',receipt.to_dict())

if __name__ == '__main__': unittest.main()
