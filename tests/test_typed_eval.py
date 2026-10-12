import json
import sys
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parents[1] / 'bench'
sys.path.insert(0, str(BENCH))

import typed_eval


class EvalSelfTests(unittest.TestCase):
    def test_fixture_count(self):
        fx = typed_eval.load_fixtures()
        self.assertGreaterEqual(len(fx), 6)
        self.assertIn('static_clean', fx)

    def test_expected_outcomes(self):
        fx = typed_eval.load_fixtures()
        # conflicting jsonld and missing field must abstain (null)
        self.assertIsNone(fx['conflicting_jsonld']['expected']['price'])
        self.assertIsNone(fx['missing_field']['expected']['price'])
        # static clean must be fully determinable
        self.assertEqual(fx['static_clean']['expected']['price'], 19.99)

    def test_deterministic_run_is_exact(self):
        result = typed_eval.run(mode='deterministic')
        self.assertEqual(result['false_positives'], 0)
        self.assertEqual(result['false_negatives'], 1)  # generic author needs fallback
        self.assertEqual(result['wrong_abstentions'], 0)
        self.assertEqual(result['precision'], 1.0)
        self.assertLess(result['recall'], 1.0)
        self.assertEqual(result['abstention_accuracy'], 1.0)
        self.assertEqual(result['model_calls'], 0)

    def test_no_fabricated_model_metrics(self):
        result = typed_eval.run(mode='deterministic')
        self.assertEqual(result['model_calls'], 0)
        self.assertIsNone(result['cost_usd'])
        self.assertIsNone(result['tokens_in'])
        self.assertIsNone(result['tokens_out'])

    def test_wrong_abstention_is_false_positive(self):
        self.assertEqual(typed_eval.classify({'x':None},{'x':'invented'}),(0,1,0,0,1))

    def test_secrets_absent_from_artifacts(self):
        result = typed_eval.run(mode='deterministic')
        text = json.dumps(result)
        for token in ('sk-', 'api_key', 'Bearer', 'authorization', 'NOUS_API_KEY'):
            self.assertNotIn(token.lower(), text.lower())


if __name__ == '__main__':
    unittest.main()
