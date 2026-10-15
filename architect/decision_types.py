"""Pure contracts for optional semantic decisions; no SDK or credential imports."""
from __future__ import annotations
import json
import math
import ipaddress
import re
from dataclasses import dataclass, field, asdict
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit

MODELS = ('jev-1.13.0', 'jev-1.14.0')


def public_url(url: str) -> str:
    if not isinstance(url, str) or len(url) > 2048 or any(c.isspace() for c in url):
        raise ValueError('public_url')
    try:
        p = urlsplit(url)
        host = p.hostname
        if (p.scheme not in ('http', 'https') or not host or p.username or p.password
                or p.fragment or p.query or p.port not in (None, 80 if p.scheme == 'http' else 443)):
            raise ValueError('public_url')
        if host.lower().rstrip('.') == 'localhost' or host.lower().rstrip('.').endswith('.localhost'):
            raise ValueError('public_url')
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and not ip.is_global:
            raise ValueError('public_url')
    except (TypeError, ValueError):
        raise ValueError('public_url') from None
    return url


@dataclass(frozen=True)
class DecisionPolicy:
    model: str = 'jev-1.13.0'
    question_set: str = 'crawler-page-v1'
    policy_version: str = 'shadow-v1'
    max_attempts: int = 5
    max_body_bytes: int = 16384
    max_questions: int = 8
    max_candidates: int = 12
    deadline_s: float = 10.0
    estimated_budget_usd: str = '0.10'
    confidence_floor: float = 0.8

    def __post_init__(self):
        if self.model not in MODELS:
            raise ValueError('model')
        for name, cap in [('max_attempts',5),('max_body_bytes',16384),
                          ('max_questions',8),('max_candidates',12)]:
            v = getattr(self,name)
            if type(v) is not int or not 1 <= v <= cap:
                raise ValueError(name)
        if type(self.deadline_s) not in (float,int) or not math.isfinite(self.deadline_s) or not 0 < self.deadline_s <= 10:
            raise ValueError('deadline')
        if type(self.confidence_floor) not in (float,int) or not math.isfinite(self.confidence_floor) or not 0 <= self.confidence_floor <= 1:
            raise ValueError('confidence_floor')
        try:
            budget = Decimal(self.estimated_budget_usd)
            if not budget.is_finite() or not 0 < budget <= Decimal('0.10'):
                raise ValueError('budget')
        except (InvalidOperation,TypeError):
            raise ValueError('budget') from None
        if not self.question_set or not self.policy_version:
            raise ValueError('policy_identity')


@dataclass(frozen=True)
class Provenance:
    source_url: str
    final_url: str
    source_sha256: str
    model_input_allowed: bool
    candidates: tuple = ()
    omitted_candidates: int = 0

    def __post_init__(self):
        public_url(self.source_url)
        public_url(self.final_url)
        if not re.fullmatch('[0-9a-f]{64}', self.source_sha256):
            raise ValueError('source_hash')
        if type(self.model_input_allowed) is not bool or type(self.omitted_candidates) is not int or self.omitted_candidates < 0:
            raise ValueError('provenance')
        # Defensive JSON copy prevents callers mutating candidate identity after construction.
        object.__setattr__(self, 'candidates', tuple(json.loads(canonical_json(list(self.candidates)))))

    def to_dict(self):
        return json.loads(canonical_json(asdict(self)))


@dataclass(frozen=True)
class ProviderResult:
    payload: dict
    request_id: str | None = None


_RECEIPT_FIELDS = frozenset(('schema_version','receipt_id','outcome','reason_code','provenance',
    'requested_model','returned_model','question_set','question_hash','input_hash','policy_version',
    'answers','annotations','usage','attempts','duration_s','estimated_cost_usd','cost_basis',
    'cache_hit','observed_at','request_id','provider','confidence_metrics','original_receipt_id'))


@dataclass(frozen=True)
class DecisionReceipt:
    data: dict = field(repr=False)

    def __post_init__(self):
        object.__setattr__(self,'data',json.loads(canonical_json({k:v for k,v in self.data.items() if k in _RECEIPT_FIELDS})))

    def to_dict(self):
        return json.loads(canonical_json(self.data))


class DecisionValidationError(ValueError):
    """Public reason code only; never include provider/user payloads."""


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode()


def _number(value, low=0.0, high=1.0):
    if type(value) not in (int, float) or not math.isfinite(value) or not low <= value <= high:
        raise DecisionValidationError('numeric_range')
    return value


def validate_questions(questions: dict) -> None:
    if type(questions) is not dict or not questions:
        raise DecisionValidationError('questions')
    for name, q in questions.items():
        if not isinstance(name, str) or not name or type(q) is not dict:
            raise DecisionValidationError('questions')
        kind = q.get('type')
        if kind == 'choice':
            c = q.get('criteria')
            if type(c) is not dict or len(c) < 2 or any(not isinstance(k, str) or not k for k in c):
                raise DecisionValidationError('criteria')
        elif kind == 'score':
            if type(q.get('criteria')) is not list or len(q['criteria']) < 2:
                raise DecisionValidationError('criteria')
        elif kind != 'noul':
            raise DecisionValidationError('question_type')
    try:
        canonical_json(questions)
    except (ValueError, TypeError):
        raise DecisionValidationError('questions') from None


def validate_response(payload: dict, questions: dict, expected_model: str) -> dict:
    validate_questions(questions)
    if type(payload) is not dict or payload.get('model') != expected_model:
        raise DecisionValidationError('model_mismatch')
    answers = payload.get('answers')
    if type(answers) is not dict or set(answers) != set(questions):
        raise DecisionValidationError('answer_names')
    clean = {}
    for name, q in questions.items():
        a = answers[name]
        kind = q['type']
        if type(a) is not dict or a.get('type') != kind:
            raise DecisionValidationError('answer_type')
        if kind == 'noul':
            clean[name] = {'type': kind, 'noul': _number(a.get('noul'))}
            continue
        criteria = q['criteria']
        labels = list(criteria) if kind == 'choice' else [str(i) for i in range(len(criteria))]
        probabilities = a.get('probabilities')
        if type(probabilities) is not dict or set(probabilities) != set(labels):
            raise DecisionValidationError('distribution_labels')
        ps = [_number(probabilities[k]) for k in labels]
        if abs(sum(ps) - 1) > 0.020000001:
            raise DecisionValidationError('distribution_sum')
        confidence = _number(a.get('confidence'))
        n = len(ps)
        peak = max(ps)
        if kind == 'choice':
            choice = a.get('choice')
            if choice not in labels or probabilities[choice] < peak:
                raise DecisionValidationError('choice')
            expected_confidence = (n * peak - 1) / (n - 1)
            clean[name] = {'type': kind, 'choice': choice, 'confidence': confidence,
                           'probabilities': probabilities}
        else:
            score = _number(a.get('score'), 0, n - 1)
            if abs(score - sum(i * p for i, p in enumerate(ps))) > 0.030000001:
                raise DecisionValidationError('score_expectation')
            legend = {str(i): v for i, v in enumerate(criteria)}
            if a.get('legend') != legend:
                raise DecisionValidationError('legend')
            m = ps.index(peak)
            mad = sum(abs(i - (n - 1) / 2) for i in range(n)) / n
            expected_confidence = max(0, 1 - sum(p * abs(i-m) for i,p in enumerate(ps)) / mad)
            clean[name] = {'type': kind, 'score': score, 'legend': legend,
                           'confidence': confidence, 'probabilities': probabilities}
        if abs(confidence - expected_confidence) > 0.020000001:
            raise DecisionValidationError('confidence_metric')
    usage = payload.get('usage')
    if type(usage) is not dict or any(type(usage.get(k)) is not int or usage[k] < 0
                                      for k in ('input_tokens', 'output_tokens')):
        raise DecisionValidationError('usage')
    return json.loads(canonical_json({'model': expected_model, 'answers': clean,
        'usage': {k: usage[k] for k in ('input_tokens', 'output_tokens')}}))
