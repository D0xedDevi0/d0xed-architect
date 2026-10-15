"""Bounded optional semantic decisions. Errors are states, never negative evidence."""
from __future__ import annotations
import asyncio
import hashlib
import re
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from decimal import Decimal
from .decision_types import (DecisionPolicy, DecisionReceipt, Provenance,
    DecisionValidationError, canonical_json, validate_questions, validate_response)
from .decision_provider import ProviderUnavailable

RATE = Decimal('0.042') / Decimal('1000000')


class DecisionEngine:
    def __init__(self, provider, policy: DecisionPolicy | None = None, cache=None):
        self.provider = provider
        self.policy = policy or DecisionPolicy()
        self.cache = cache
        self.attempts = 0
        self.spent = Decimal(0)
        self.closed = False
        self._lock = threading.Lock()

    def evaluate(self, state: dict, questions: dict, provenance: Provenance,
                 policy: DecisionPolicy | None = None) -> DecisionReceipt:
        with self._lock:
            return self._evaluate(state, questions, provenance, policy or self.policy)

    def _evaluate(self, state, questions, provenance, policy):
        start = time.monotonic()
        p = policy
        record = {'schema_version':'jev-decision-v1','receipt_id':uuid.uuid4().hex,
            'outcome':'unavailable','reason_code':'not_evaluated','provenance':provenance.to_dict(),
            'requested_model':p.model,'returned_model':None,'question_set':p.question_set,
            'policy_version':p.policy_version,'answers':{},'annotations':{},'usage':None,
            'attempts':0,'duration_s':0.0,'estimated_cost_usd':None,
            'cost_basis':'published input rate $0.042/M; estimated, not billing ceiling',
            'cache_hit':False,'observed_at':datetime.now(timezone.utc).isoformat(),
            'request_id':None,'provider':getattr(self.provider,'identity','test-only'),
            'confidence_metrics':{'choice':'top_above_uniform','score':'ordinal_distance','noul':'probability_only'}}

        def finish(outcome, reason):
            record.update(outcome=outcome,reason_code=reason,duration_s=round(time.monotonic()-start,6))
            return DecisionReceipt(record)

        if not provenance.model_input_allowed:
            return finish('denied','model_input_not_allowed')
        try:
            validate_questions(questions)
            body = {'model':p.model,'state':state,'questions':questions}
            import json
            raw = json.dumps(body,separators=(',', ':'),ensure_ascii=True,allow_nan=False).encode()
            # Preserve choice insertion order: option-order bias is observable behavior.
            body = json.loads(raw)
            questions = body['questions']
            record['question_hash'] = hashlib.sha256(json.dumps(questions,separators=(',', ':'),ensure_ascii=True,allow_nan=False).encode()).hexdigest()
            record['input_hash'] = hashlib.sha256(raw).hexdigest()
        except (ValueError,TypeError):
            return finish('invalid_response','invalid_request')
        if len(raw) > p.max_body_bytes or len(questions) > p.max_questions or len(provenance.candidates) > p.max_candidates:
            return finish('budget_exhausted','request_limit')
        key = hashlib.sha256(canonical_json({'wire_body':raw.decode(),'provider':record['provider'],
                                               'provenance':provenance.to_dict(),'policy':asdict(p)})).hexdigest()
        if self.cache:
            try:
                cached = self.cache.get(key)
                if cached:
                    valid = validate_response(cached['payload'],questions,p.model)
                    record.update(answers=valid['answers'],returned_model=valid['model'],
                        usage=valid['usage'],cache_hit=True,observed_at=cached['observed_at'],
                        original_receipt_id=cached['receipt_id'],estimated_cost_usd='0',
                        provider=cached['provider'])
                    record['annotations'] = self._annotations(valid['answers'],p)
                    outcome='abstained' if any(v['status']=='abstained' for v in record['annotations'].values()) else 'ok'
                    return finish(outcome,'cached')
            except (ValueError,OSError,KeyError,TypeError):
                return finish('invalid_response','cache_invalid')
        if self.closed or self.attempts >= min(p.max_attempts,self.policy.max_attempts):
            return finish('budget_exhausted','run_closed_or_attempt_limit')
        reservation = Decimal(len(raw)) * RATE
        if self.spent + reservation > min(Decimal(p.estimated_budget_usd),Decimal(self.policy.estimated_budget_usd)):
            return finish('budget_exhausted','estimated_cost_guard')
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            return finish('unavailable','sync_api_in_async_context')
        self.attempts += 1
        record['attempts'] = 1
        self.spent += reservation
        try:
            result = asyncio.run(self._ask(body,p.deadline_s))
            payload = validate_response(result.payload, questions, p.model)
            record.update(returned_model=payload['model'],answers=payload['answers'],usage=payload['usage'])
            cost = Decimal(payload['usage']['input_tokens']) * RATE
            self.spent += cost - reservation
            record['estimated_cost_usd'] = str(cost)
            rid = result.request_id
            record['request_id'] = rid if isinstance(rid,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',rid) else None
            record['annotations'] = self._annotations(payload['answers'],p)
        except ProviderUnavailable:
            self.closed=True
            return finish('unavailable','credential_or_optional_dependency_unavailable')
        except TimeoutError:
            self.closed=True
            return finish('timeout','provider_deadline')
        except DecisionValidationError as exc:
            self.closed=True
            return finish('invalid_response',str(exc))
        except Exception:
            self.closed=True
            return finish('provider_error','provider_failure')
        outcome = 'abstained' if any(v['status']=='abstained' for v in record['annotations'].values()) else 'ok'
        if self.cache:
            try:
                self.cache.put(key,{'payload':payload,'observed_at':record['observed_at'],
                                   'receipt_id':record['receipt_id'],'provider':record['provider']})
            except (OSError,ValueError,TypeError):
                # Preserve completed paid result, explicitly signal persistence failure.
                return finish(outcome,'completed_cache_write_failed')
        return finish(outcome,'evaluated')

    async def _ask(self, body, deadline):
        async with asyncio.timeout(deadline):
            return await self.provider.ask(body)

    @staticmethod
    def _annotations(answers,p):
        annotations={}
        for key,a in answers.items():
            abstain = a.get('choice') in ('unknown','none') or (
                'confidence' in a and a['confidence'] < p.confidence_floor)
            annotations[key]={'status':'abstained' if abstain else 'observed',
                              'shadow_only':True}
        return annotations
