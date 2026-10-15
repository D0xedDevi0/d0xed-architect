import json
import os
from pathlib import Path
import tempfile
import unittest
from architect.decision_cache import DecisionCache
from architect.decision_engine import DecisionEngine
from architect.decision_types import DecisionPolicy
from test_decision_engine import SyntheticProvider, provenance
from test_decision_types import QUESTIONS

class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'cache';self.cache=DecisionCache(self.root)

    def test_private_roundtrip_and_tamper(self):
        key='a'*64;self.cache.put(key,{'payload':{'data':'public'}})
        self.assertEqual(self.cache.get(key),{'payload':{'data':'public'}})
        f=self.root/(key+'.json')
        self.assertEqual(f.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.root.stat().st_mode & 0o777,0o700)
        f.write_text('{}')
        with self.assertRaises(ValueError):self.cache.get(key)

    def test_symlinks_and_repository_locations_refused(self):
        outside=Path(self.tmp.name)/'outside';outside.write_text('untouched')
        (self.root/('a'*64+'.json')).symlink_to(outside)
        with self.assertRaises((ValueError,OSError)):self.cache.get('a'*64)
        with self.assertRaises((ValueError,OSError)):self.cache.put('a'*64,{})
        with self.assertRaises(ValueError):DecisionCache(Path.cwd()/'new-cache-must-not-exist')
        link=Path(self.tmp.name)/'link';link.symlink_to(self.root)
        with self.assertRaises(ValueError):DecisionCache(link)
        self.assertEqual(outside.read_text(),'untouched')

    def test_engine_cache_identity_and_usage(self):
        p=SyntheticProvider();e=DecisionEngine(p,DecisionPolicy(),self.cache)
        one=e.evaluate({'text':'public'},QUESTIONS,provenance()).to_dict()
        two=e.evaluate({'text':'public'},QUESTIONS,provenance()).to_dict()
        self.assertTrue(two['cache_hit']);self.assertEqual(two['attempts'],0)
        self.assertEqual(two['observed_at'],one['observed_at'])
        self.assertEqual(two['estimated_cost_usd'],'0')
        e.evaluate({'text':'different'},QUESTIONS,provenance())
        self.assertEqual(len(p.calls),2)

    def test_invalid_cached_response_not_trusted_even_with_valid_hash(self):
        p=SyntheticProvider();e=DecisionEngine(p,DecisionPolicy(),self.cache)
        e.evaluate({},QUESTIONS,provenance())
        f=next(self.root.glob('*.json'));key=f.stem
        value=self.cache.get(key);value['payload']['model']='jev-latest';self.cache.put(key,value)
        self.assertEqual(e.evaluate({},QUESTIONS,provenance()).to_dict()['outcome'],'invalid_response')
        self.assertEqual(len(p.calls),1)
