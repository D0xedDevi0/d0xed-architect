"""Explicit public-page Jev lane. Never used for private repo or wallet actions."""
from __future__ import annotations
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time
from datetime import datetime, timezone


def resolve_jev_key(env=None):
    env=os.environ if env is None else env
    directory=env.get('CREDENTIALS_DIRECTORY')
    if directory:
        try:
            key=(Path(directory)/'typesafe_api_key').read_text().strip()
            if key:return key
        except OSError:pass
    return (env.get('TYPESAFE_API_KEY') or '').strip() or None


class JevBudget:
    """Persistent fail-closed request reservations: no refund after uncertain outcomes."""
    def __init__(self,root:Path,*,daily_limit=20,min_gap=30.0):
        if type(daily_limit) is not int or not 1<=daily_limit<=50:
            raise ValueError('daily_limit')
        if type(min_gap) not in (float,int) or not math.isfinite(min_gap) or min_gap<0:
            raise ValueError('min_gap')
        from architect.decision_cache import DecisionCache
        self.root=DecisionCache(root).root
        self.daily_limit=daily_limit;self.min_gap=min_gap

    def reserve(self,request_id:str,*,now=None):
        if not isinstance(request_id,str) or not request_id or len(request_id)>128:
            raise ValueError('request_id')
        now=time.time() if now is None else now
        if type(now) not in (float,int) or not math.isfinite(now) or now<0:
            raise ValueError('clock')
        today=datetime.fromtimestamp(now,timezone.utc).date().isoformat()
        marker=hashlib.sha256(request_id.encode()).hexdigest()
        from architect.decision_cache import DecisionCache
        directory=DecisionCache(self.root)._open_root()
        lock=None
        try:
            lock=os.open('budget.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600,dir_fd=directory)
            st=os.fstat(lock)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:
                raise ValueError('budget_lock')
            fcntl.flock(lock,fcntl.LOCK_EX)
            try:fd=os.open('budget.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
            except FileNotFoundError:state={'schema':'devin-jev-budget-v1','day':today,'last':0,'requests':[]}
            else:
                with os.fdopen(fd,'rb') as f:
                    st=os.fstat(f.fileno())
                    if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.getuid() or st.st_mode&0o077:
                        raise ValueError('budget_file')
                    raw=f.read(16385)
                try:state=json.loads(raw)
                except (ValueError,UnicodeError):raise ValueError('budget_corrupt') from None
                if (len(raw)>16384 or type(state) is not dict or set(state)!={'schema','day','last','requests'} or
                    state['schema']!='devin-jev-budget-v1' or not isinstance(state['day'],str) or
                    not re.fullmatch(r'\d{4}-\d{2}-\d{2}',state['day']) or
                    type(state['last']) not in (int,float) or not math.isfinite(state['last']) or state['last']<0 or
                    type(state['requests']) is not list or len(state['requests'])>50 or
                    len(set(state['requests']))!=len(state['requests']) or
                    any(not isinstance(x,str) or not re.fullmatch('[0-9a-f]{64}',x) for x in state['requests'])):
                    raise ValueError('budget_corrupt')
                if today<state['day'] or now<state['last']:return False
                if today>state['day']:state={'schema':'devin-jev-budget-v1','day':today,'last':0,'requests':[]}
            if marker in state['requests'] or len(state['requests'])>=self.daily_limit or (state['last'] and now-state['last']<self.min_gap):
                return False
            state['requests'].append(marker);state['last']=now
            from architect.judge_cli import write_report
            write_report(self.root/'budget.json',state)
            return True
        finally:
            if lock is not None:os.close(lock)
            os.close(directory)


class JevLane:
    def __init__(self,key,budget):
        self._key=key;self._budget=budget

    def __call__(self,url,objective,request_id):
        if not self._key or self._budget is None:return '🟦 Jev is unavailable. No semantic call made.'
        try:
            if not self._budget.reserve(request_id):
                return '🟦 Jev request limit, cooldown or duplicate guard. No new semantic call.'
            from architect.semantic import fetch_judgment_page,annotate_page
            from architect.decision_engine import DecisionEngine
            from architect.decision_provider import JevProvider
            from architect.decision_types import DecisionPolicy
            from architect.judge_cli import write_report
            fetched=fetch_judgment_page(url)
            engine=DecisionEngine(JevProvider(self._key),DecisionPolicy(max_attempts=1))
            result=annotate_page(fetched,objective,engine,operator_allows_model_input=True,source_url=url)
            digest=hashlib.sha256(request_id.encode()).hexdigest()
            write_report(self._budget.root/(digest+'.receipt.json'),result)
            return render_jev(result,digest)
        except Exception:
            return '🟦 Jev read unavailable or refused. Access rules stay intact; no automatic retry.'


def render_jev(result,receipt_id):
    decision=result.get('decision',{});answers=decision.get('answers',{})
    outcome=decision.get('outcome','unavailable')
    lines=['🟦 DEVin · Jev public-page read',f'🟦 Result: {outcome} (shadow-only)']
    purpose=answers.get('purpose',{})
    if purpose:lines.append('🟦 Purpose: '+purpose['choice']+f" · confidence {purpose['confidence']:.2f}")
    relevance=answers.get('relevance',{})
    if relevance:lines.append(f"🟦 Relevance: {relevance['score']:.2f}/2 · confidence {relevance['confidence']:.2f}")
    if decision.get('returned_model'):lines.append('🟦 Model: '+decision['returned_model'])
    if result.get('source_sha256'):lines.append('🟦 Source SHA-256: '+result['source_sha256'])
    lines.append('🟦 Receipt: '+receipt_id)
    lines.append('Evidence ranking, not a safety verdict. Uncertainty stays visible.')
    return '\n'.join(lines)


def make_jev_lane(env=None):
    env=os.environ if env is None else env
    if env.get('DEVIN_JEV_ENABLED')!='1':return None
    key=resolve_jev_key(env)
    root=env.get('DEVIN_JEV_STATE')
    if not key or not root:return None
    try:return JevLane(key,JevBudget(Path(root),daily_limit=int(env.get('DEVIN_JEV_DAILY_LIMIT','20'))))
    except (ValueError,OSError):return None
