"""Strict, bounded declarative field schemas; no executable selectors."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass

_TYPES = {'string', 'number', 'boolean', 'string[]'}
_SELECTORS = {'title','description','canonical','lang','h1','headings','links','text'}
_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_]{0,63}\Z')
_PROP = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,63}\Z')


@dataclass(frozen=True)
class FieldSpec:
    type: str
    selector: str | None = None
    hint: str = ''
    required: bool = False


def parse_schema(schema_json: str) -> dict[str, FieldSpec]:
    if not isinstance(schema_json, str) or len(schema_json.encode('utf-8')) > 8192:
        raise ValueError('schema must be a JSON string of at most 8192 bytes')
    try:
        obj = json.loads(schema_json, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError) as e:
        raise ValueError(f'invalid schema JSON: {e}') from None
    if not isinstance(obj, dict) or not 1 <= len(obj) <= 16:
        raise ValueError('schema must have 1 to 16 fields')
    result = {}
    for name, item in obj.items():
        if not isinstance(name, str) or not _NAME.fullmatch(name) or name.startswith('__'):
            raise ValueError('invalid field name')
        if not isinstance(item, dict) or not set(item) <= {'type','selector','hint','required'}:
            raise ValueError(f'invalid field specification: {name}')
        kind, selector = item.get('type'), item.get('selector')
        hint, required = item.get('hint', ''), item.get('required', False)
        if kind not in _TYPES or not isinstance(required, bool) or not isinstance(hint, str) or len(hint)>240:
            raise ValueError(f'invalid field type, hint or required: {name}')
        if selector is not None and (not isinstance(selector, str) or
            (selector not in _SELECTORS and not (selector.startswith('jsonld:') and _PROP.fullmatch(selector[7:])))):
            raise ValueError(f'invalid selector: {name}')
        result[name] = FieldSpec(kind, selector, hint, required)
    return result


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def schema_dict(specs: dict[str, FieldSpec]) -> dict:
    return {name: {'type': s.type, 'selector': s.selector, 'hint': s.hint, 'required': s.required}
            for name, s in specs.items()}
