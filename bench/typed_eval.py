"""Evidence-backed evaluation of typed extraction over fixed local fixtures.

Runs the real pipeline (schema -> deterministic -> optional bounded model) with an
injected transport so no network is touched. Reports precision, recall, and
abstention accuracy, plus wall time, model calls/tokens, and cost status. Secrets
and credential-bearing headers are never written to any output artifact.
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from architect.http import Response
from architect.safe_fetch import AccessResult, AccessDenied
from architect.typed import extract_typed
from architect.portal_extract import portal_provider

FIXTURES = Path(__file__).parent / "typed_fixtures.json"


def load_fixtures():
    return json.loads(FIXTURES.read_text())


def make_fetcher(html: str, signals=None, denied=False):
    body = html.encode()
    def fetcher(url, **kw):
        if denied:
            raise AccessDenied('robots disallows page')
        return AccessResult(Response(url, 200, {}, body, 'text/html'), signals or {})
    return fetcher


def classify(expected, values):
    """Return (tp, fp, fn, correct_abstain, wrong_abstain)."""
    tp = fp = fn = correct_abstain = wrong_abstain = 0
    for name, want in expected.items():
        got = values.get(name)
        if want is None:
            if got is None:
                correct_abstain += 1
            else:
                fp += 1
                wrong_abstain += 1
        else:
            if got == want:
                tp += 1
            elif got is None:
                fn += 1
            else:
                fp += 1
    return tp, fp, fn, correct_abstain, wrong_abstain


def run(mode: str = 'deterministic', model=None) -> dict:
    fixtures = load_fixtures()
    tp = fp = fn = correct_abstain = wrong_abstain = 0
    total_model_calls = 0
    token_in = token_out = 0
    cost = 0.0
    cost_known = True
    per_fixture = []
    t0 = time.time()
    for name, fx in fixtures.items():
        use_llm = mode in ('llm', 'both')
        out = extract_typed(f'https://fixture.local/{name}', json.dumps(fx['schema']),
                            use_llm=use_llm,
                            fetcher=make_fetcher(fx['html'], fx.get('signals'),fx.get('robots_denied',False)),
                            model=model)
        f_tp, f_fp, f_fn, f_ca, f_wa = classify(fx['expected'], out['values'])
        tp += f_tp; fp += f_fp; fn += f_fn; correct_abstain += f_ca; wrong_abstain += f_wa
        calls = out['llm'].get('calls', 0)
        total_model_calls += calls
        usage = out['llm'].get('usage') or {}
        if calls:
            if (token_in is not None and token_out is not None and
                isinstance(usage.get('prompt_tokens'), int) and isinstance(usage.get('completion_tokens'), int)):
                token_in += usage['prompt_tokens']; token_out += usage['completion_tokens']
            else:
                token_in = token_out = None
            if out['llm'].get('cost_source')=='provider_reported' and out['llm'].get('cost_usd') is not None:
                cost += out['llm']['cost_usd']
            else:
                cost_known = False
        per_fixture.append({
            'name': name, 'tp': f_tp, 'fp': f_fp, 'fn': f_fn,
            'correct_abstain': f_ca, 'wrong_abstain': f_wa,
            'model_calls': calls, 'model_error': out['llm'].get('error'),
        })
    wall = round(time.time() - t0, 3)
    filled = tp + fp
    precision = round(tp / filled, 4) if filled else None
    recall_denom = tp + fn
    recall = round(tp / recall_denom, 4) if recall_denom else None
    abstain_denom = correct_abstain + wrong_abstain
    abstention = round(correct_abstain / abstain_denom, 4) if abstain_denom else None
    return {
        'mode': mode,
        'fixtures': len(fixtures),
        'precision': precision,
        'recall': recall,
        'abstention_accuracy': abstention,
        'true_positives': tp, 'false_positives': fp,
        'false_negatives': fn, 'wrong_abstentions': wrong_abstain,
        'model_calls': total_model_calls,
        'tokens_in': token_in if total_model_calls and token_in is not None else None,
        'tokens_out': token_out if total_model_calls and token_out is not None else None,
        'cost_usd': round(cost,8) if total_model_calls and cost_known else None,
        'cost_source': 'provider_reported' if total_model_calls and cost_known else 'unknown',
        'wall_seconds': wall,
        'per_fixture': per_fixture,
        'note': 'small handcrafted fixture evaluation, not production accuracy; costs are provider-reported, not pre-call guarantees',
    }


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('--mode', choices=['deterministic', 'llm', 'both'], default='deterministic')
    ap.add_argument('--output', type=Path, default=Path(__file__).parent / 'typed-results.json')
    ap.add_argument('--allow-live-model', action='store_true', help='explicitly permit paid Nous calls')
    args = ap.parse_args(argv)
    if args.mode in ('llm','both') and not args.allow_live_model:
        ap.error('--mode llm/both requires --allow-live-model')
    model = portal_provider if args.allow_live_model else None
    result = ({'deterministic': run('deterministic'), 'llm': run('llm',model=model)}
              if args.mode=='both' else run(args.mode, model=model))
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
