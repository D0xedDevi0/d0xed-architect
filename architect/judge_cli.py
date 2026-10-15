"""Separate opt-in sidecar command; legacy commands never import this module."""
from __future__ import annotations
import json
import os
from pathlib import Path
import stat
import uuid
from .semantic import fetch_judgment_page, annotate_page, safe_text
from .decision_types import DecisionPolicy, public_url


def make_engine(args):
    from .decision_engine import DecisionEngine
    from .decision_provider import JevProvider
    from .decision_cache import DecisionCache
    cache=DecisionCache(Path(args.cache_dir)) if args.cache_dir else None
    return DecisionEngine(JevProvider(),DecisionPolicy(model=args.model),cache)


def _output_path(raw):
    path=Path(raw).absolute()
    for p in (path,*path.parents):
        if p.is_symlink():raise ValueError('output_symlink')
    if not path.parent.is_dir():raise ValueError('output_parent_missing')
    if path.exists() and (not path.is_file() or path.stat().st_uid!=os.getuid()):
        raise ValueError('output_not_owned_file')
    return path


def write_report(path: Path, value: dict):
    path=_output_path(path)
    raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    root=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    temp='.'+uuid.uuid4().hex
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=root)
        with os.fdopen(fd,'wb') as f:
            f.write(raw);f.flush();os.fsync(f.fileno())
        os.replace(temp,path.name,src_dir_fd=root,dst_dir_fd=root)
        os.fsync(root)
    finally:
        try:os.unlink(temp,dir_fd=root)
        except FileNotFoundError:pass
        os.close(root)


def cmd_judge_page(args) -> int:
    try:
        path=_output_path(args.out)
        public_url(args.url)
        if not args.objective.strip() or not safe_text(args.objective) or len(args.objective.encode())>1024:
            raise ValueError('objective')
    except (ValueError,OSError):
        print('[architect] invalid public input or output path')
        return 2
    try:
        fetched=fetch_judgment_page(args.url)
        engine=None if args.offline else make_engine(args)
        report=annotate_page(fetched,args.objective,engine,
            operator_allows_model_input=args.allow_model_input,source_url=args.url)
    except (ValueError,PermissionError):
        report={'schema_version':'jev-page-v1','decision':{'outcome':'denied','reason_code':'input_or_access_denied'}}
    except Exception:
        report={'schema_version':'jev-page-v1','decision':{'outcome':'provider_error','reason_code':'acquisition_or_configuration_failed'}}
    try:
        write_report(path,report)
    except (OSError,ValueError):
        print('[architect] report write failed')
        return 2
    outcome=report['decision']['outcome']
    print('[architect] semantic outcome: '+outcome)
    if outcome=='denied':return 2
    if outcome in ('ok','abstained') or (args.offline and outcome=='unavailable'):return 0
    return 1
