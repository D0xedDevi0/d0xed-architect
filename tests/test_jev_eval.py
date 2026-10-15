import importlib.util
from pathlib import Path
import unittest

class EvalTests(unittest.TestCase):
    def test_fixed_corpus_and_honest_offline_summary(self):
        path=Path(__file__).resolve().parents[1]/'bench/jev_eval.py'
        spec=importlib.util.spec_from_file_location('jev_eval',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        rows=module.load_cases()
        self.assertEqual(len(rows),5)
        self.assertEqual(len({r['id'] for r in rows}),5)
        self.assertTrue(all(r['label_source']=='agent_authored_synthetic' for r in rows))
        report=module.run_evaluation(rows,live=False)
        self.assertEqual(report['cases_total'],5)
        self.assertEqual(report['provider_attempts'],0)
        self.assertEqual(report['evaluated'],0)
        self.assertEqual(report['unexecuted'],5)

    def test_permutation_preserves_labels(self):
        path=Path(__file__).resolve().parents[1]/'bench/jev_eval.py'
        spec=importlib.util.spec_from_file_location('jev_eval',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self.assertEqual(module.compare_choices({'choice':'a'},{'choice':'a'}),'same')
        self.assertEqual(module.compare_choices({'choice':'a'},{'choice':'b'}),'different')
        self.assertEqual(module.compare_choices({},{}),'unexecuted')
