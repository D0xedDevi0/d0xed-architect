"""Lazy official Jev SDK transport. No vault or credential filesystem access."""
from __future__ import annotations
import logging
import os
from typing import Protocol
from .decision_types import ProviderResult, MODELS, canonical_json


class ProviderUnavailable(RuntimeError):
    pass


class ProviderFailure(RuntimeError):
    pass


class AsyncDecisionProvider(Protocol):
    identity: str
    async def ask(self, body: dict) -> ProviderResult: ...


class JevProvider:
    identity = 'typesafe-hosted'

    def __init__(self, api_key: str | None = None, *, transport=None):
        self._key = api_key
        self._transport = transport  # injected only by tests; not exposed by CLI

    async def ask(self, body: dict) -> ProviderResult:
        key = self._key or os.environ.get('TYPESAFE_API_KEY')
        if not key:
            raise ProviderUnavailable('missing_key')
        try:
            import httpx2
            from typesafe_sdk import AsyncTypeSafeClient, RetryPolicy
        except ImportError:
            raise ProviderUnavailable('missing_jev_extra') from None
        if body.get('model') not in MODELS or len(canonical_json(body)) > 16384:
            raise ProviderFailure('invalid_request')
        # SDK debug output includes bodies: never allow it onto application handlers.
        logging.getLogger('typesafe_sdk').disabled = True
        request_id = None

        async def check_request(request):
            if str(request.url) != 'https://api.typesafe.ai/v1/systemone' or request.method != 'POST':
                raise ProviderFailure('endpoint')
            if len(request.content) > 16384:
                raise ProviderFailure('body_limit')

        async def capture_response(response):
            nonlocal request_id
            raw = response.headers.get('x-typesafe-request-id')
            if raw and len(raw) <= 128 and all(c.isalnum() or c in '_-' for c in raw):
                request_id = raw
            if 300 <= response.status_code < 400:
                raise ProviderFailure('redirect')

        try:
            async with httpx2.AsyncClient(follow_redirects=False, trust_env=False,
                    timeout=10.0, transport=self._transport,
                    event_hooks={'request':[check_request], 'response':[capture_response]}) as http:
                async with AsyncTypeSafeClient(api_key=key, model=body['model'],
                        base_url='https://api.typesafe.ai', compression=False,
                        retry=RetryPolicy(max_retries=0), timeout=10.0, http_client=http) as client:
                    result = await client.system_one(state=body['state'], questions=body['questions'],
                                                     model=body['model'])
                    return ProviderResult(result.model_dump(mode='json'), request_id)
        except ProviderFailure:
            raise
        except Exception:
            raise ProviderFailure('request_failed') from None
