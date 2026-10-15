import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from architect.cli import main
from architect import judge_cli
from test_semantic import page, PageProvider
from architect.decision_engine import DecisionEngine

class JudgeCliTests(unittest.TestCase):
    def test_offline_and_real_command_wiring(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'receipt.json'
            for offline in [True,False]:
                provider=PageProvider()
                with patch.object(judge_cli,'fetch_judgment_page',return_value=page()), \
                     patch.object(judge_cli,'make_engine',return_value=DecisionEngine(provider)), \
                     contextlib.redirect_stdout(io.StringIO()):
                    args=['judge-page','https://example.org/page','--objective','Find SDK docs','--out',str(path)]
                    if offline:args+=['--offline']
                    self.assertEqual(main(args),0)
                report=json.loads(path.read_text())
                self.assertEqual(report['decision']['outcome'],'unavailable' if offline else 'ok')
                self.assertEqual(len(provider.calls),0 if offline else 1)
                self.assertEqual(path.stat().st_mode&0o777,0o600)

    def test_denial_and_missing_key_are_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'receipt.json'
            with patch.object(judge_cli,'fetch_judgment_page',return_value=page(signals={'ai-input':'no'})),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['judge-page','https://example.org/page','--objective','docs','--out',str(path)]),2)
            with patch.object(judge_cli,'fetch_judgment_page',return_value=page()),patch.dict('os.environ',{},clear=True),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['judge-page','https://example.org/page','--objective','docs','--out',str(path)]),1)
            self.assertEqual(json.loads(path.read_text())['decision']['outcome'],'unavailable')

    def test_symlink_output_refused_without_fetch_or_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'target';target.write_text('keep')
            out=Path(tmp)/'link';out.symlink_to(target)
            with patch.object(judge_cli,'fetch_judgment_page') as fetch,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['judge-page','https://example.org/page','--objective','docs','--out',str(out)]),2)
            self.assertEqual(target.read_text(),'keep');fetch.assert_not_called()
