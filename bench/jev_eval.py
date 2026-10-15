"""Small synthetic Jev smoke evaluation; not human ground truth or a quality benchmark."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from architect.decision_engine import DecisionEngine
from architect.decision_provider import JevProvider
from architect.decision_types import DecisionPolicy, Provenance
from architect.semantic import page_questions


def load_cases():
    rows=json.loads(Path(__file__).with_name('jev_fixtures.json').read_text())
    if len({r['id'] for r in rows}) != len(rows) or any(r['label_source']!='agent_authored_synthetic' for r in rows):
        raise ValueError('invalid_corpus')
    return rows


def compare_choices(a,b):
    if not a.get('choice') or not b.get('choice'):return 'unexecuted'
    return 'same' if a['choice']==b['choice'] else 'different'


def run_evaluation(rows, *, live=False, model='jev-1.13.0', permute=False, provider=None):
    engine=DecisionEngine(provider or JevProvider(),DecisionPolicy(model=model)) if live else None
    results=[]
    for case in rows:
        digest=hashlib.sha256(case['text'].encode()).hexdigest()
        candidates=([{'id':'span_0','excerpt':case['text'],'byte_offset':0,'source_sha256':digest}]
                    if case['text'] else [])
        prov=Provenance('https://example.org/synthetic','https://example.org/synthetic',digest,True,tuple(candidates))
        questions=page_questions(candidates)
        variants=[('base',questions)]
        if permute:
            reverse=json.loads(json.dumps(questions))
            for q in reverse.values():
                if q['type']=='choice':q['criteria']=dict(reversed(list(q['criteria'].items())))
            variants.append(('reversed',reverse))
        records=[]
        for variant,q in variants:
            if engine is None:receipt={'outcome':'unavailable','reason_code':'offline','answers':{}}
            else:receipt=engine.evaluate({'objective':case['objective'],'candidates':candidates},q,prov).to_dict()
            purpose=receipt.get('answers',{}).get('purpose',{}).get('choice')
            score=receipt.get('answers',{}).get('relevance',{}).get('score')
            checks=[]
            if purpose is not None:checks.append(purpose in case['expected_purpose'])
            if 'expected_relevance_max' in case and score is not None:
                checks.append(score<=case['expected_relevance_max'])
            records.append({'variant':variant,'receipt':receipt,
                            'synthetic_expectation_match':all(checks) if checks else None})
        comparison=compare_choices(records[0]['receipt'].get('answers',{}).get('purpose',{}),
            records[1]['receipt'].get('answers',{}).get('purpose',{})) if len(records)>1 else 'unexecuted'
        results.append({'case_id':case['id'],'label_source':case['label_source'],'variants':records,'option_order':comparison})
    all_records=[v for r in results for v in r['variants']]
    valid=[v for v in all_records if v['receipt']['outcome'] in ('ok','abstained')]
    return {'corpus_kind':'agent_authored_synthetic','model':model,'cases_total':len(rows),
        'variants_total':len(all_records),'evaluated':len(valid),'unexecuted':len(all_records)-len(valid),
        'abstained':sum(v['receipt']['outcome']=='abstained' for v in all_records),
        'provider_attempts':engine.attempts if engine else 0,
        'estimated_cost_usd':str(engine.spent) if engine else '0',
        'cost_note':'Includes conservative reservations on failed attempts; estimated, not invoice.',
        'limitations':['Synthetic labels authored by implementation agent; not human ground truth.',
                      'At most five attempts shared across every case/option-order variant.',
                      'No generalized quality, calibration or model comparison claim.'],
        'results':results}


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--live',action='store_true')
    p.add_argument('--permute',action='store_true')
    p.add_argument('--model',choices=('jev-1.13.0','jev-1.14.0'),default='jev-1.13.0')
    p.add_argument('--out',required=True)
    args=p.parse_args(argv)
    report=run_evaluation(load_cases(),live=args.live,model=args.model,permute=args.permute)
    from architect.judge_cli import write_report
    write_report(Path(args.out),report)
    print(json.dumps({k:report[k] for k in ('cases_total','evaluated','unexecuted','provider_attempts','estimated_cost_usd')}))
    return 0

if __name__=='__main__':raise SystemExit(main())
