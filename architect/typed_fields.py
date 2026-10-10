"""Deterministic typed fields with literal source evidence; no model or IO."""
from __future__ import annotations
import hashlib
import json
import re
from architect.extract import Page
from architect.typed_schema import FieldSpec


def _typed(value, kind):
    if kind == 'string':
        return value if isinstance(value,str) and value else None
    if kind == 'number':
        if isinstance(value,bool): return None
        if isinstance(value,(int,float)) and not isinstance(value,complex): return value
        if isinstance(value,str) and re.fullmatch(r'-?(?:0|[1-9]\d*)(?:\.\d+)?',value.strip()):
            return float(value) if '.' in value else int(value)
    if kind == 'boolean':
        if type(value) is bool: return value
        if isinstance(value,str) and value.lower() in ('true','false'): return value.lower()=='true'
    if kind == 'string[]' and isinstance(value,list) and value and all(isinstance(v,str) and v for v in value):
        return value
    return None


def verify_candidate(value: object, kind: str, excerpt: str, source: str) -> bool:
    if not isinstance(excerpt,str) or not excerpt or excerpt not in source or len(excerpt)>1000:
        return False
    v=_typed(value,kind)
    if v is None: return False
    if kind=='string': return v.strip() in excerpt
    if kind=='number':
        return any(_typed(m.group(), 'number') == v for m in re.finditer(r'-?(?:0|[1-9]\d*)(?:\.\d+)?',excerpt))
    if kind=='boolean': return bool(re.search(r'\b'+str(v).lower()+r'\b',excerpt,re.I))
    if kind=='string[]': return all(item in excerpt for item in v)
    return False


def deterministic_fields(page: Page, specs: dict[str,FieldSpec], source: bytes) -> tuple[dict,dict]:
    raw=source.decode('utf-8','replace')
    digest=hashlib.sha256(source).hexdigest()
    values,meta={},{}
    simple={'title':page.title,'description':page.description,'canonical':page.canonical,
            'lang':page.lang,'h1':next((t for level,t in page.headings if level==1),''),
            'headings':[t for _,t in page.headings],
            'links':[href for href,_ in page.links],
            'text':page.text}
    for name,spec in specs.items():
        selector=spec.selector or (name if name in simple else None)
        candidate=None
        locator=selector
        if selector and selector.startswith('jsonld:'):
            property_name=selector[7:]
            matches=[(i,item[property_name]) for i,item in enumerate(page.json_ld)
                     if isinstance(item,dict) and property_name in item]
            if matches and all(value==matches[0][1] for _,value in matches):
                locator=f'jsonld[{matches[0][0]}].{property_name}'
                candidate=matches[0][1]
        elif selector in simple:
            candidate=simple[selector]
            if selector=='text' and spec.hint:
                candidate=next((line.strip() for line in page.text.splitlines() if spec.hint.lower() in line.lower()),None)
        converted=_typed(candidate,spec.type)
        excerpt=None
        if converted is not None and selector=='text' and not spec.hint:
            nodes=page.text_nodes
            if (nodes and len(nodes)<=32 and sum(len(n) for n in nodes)<=1000
                    and all(n in raw for n in nodes)):
                excerpt=list(nodes)  # exact visible DOM data, not normalized cross-tag HTML
            else:
                converted=None  # no complete, bounded verbatim evidence
        elif converted is not None:
            items=converted if isinstance(converted,list) else [converted]
            evidence=[]
            for item in items:
                variants=[str(item).lower() if isinstance(item,bool) else str(item)]
                if isinstance(item,str): variants.insert(0,item)
                literal=next((s for s in variants if s in raw),None)
                if literal is None:
                    evidence=[]
                    break
                evidence.append(literal)
            if evidence:
                if selector and selector.startswith('jsonld:'):
                    prop=re.escape(selector[7:])
                    pattern=(r'''["']'''+prop+r'''["']\s*:\s*["']?'''+
                             re.escape(evidence[0])+r'''["']?(?=\s*[,}\]]|$)''')
                    match=re.search(pattern,raw)
                    if match:
                        excerpt=raw[match.start():match.end()]
                    else:
                        converted=None  # no property-anchored literal evidence
                else:
                    excerpt=evidence if isinstance(converted,list) else evidence[0]
            else:
                converted=None
        values[name]=converted
        meta[name]={'method':'deterministic' if converted is not None else 'missing',
                    'source_excerpt':excerpt,'locator':locator if converted is not None else None,
                    'source_sha256':digest}
    return values,meta
