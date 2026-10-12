import json
import unittest
from architect.typed_schema import parse_schema, schema_dict


class SchemaTests(unittest.TestCase):
    def test_parses_canonical_price(self):
        specs = parse_schema('{"price":{"type":"number","selector":"jsonld:price"}}')
        self.assertEqual(specs['price'].type, 'number')
        self.assertEqual(specs['price'].selector, 'jsonld:price')
        self.assertEqual(schema_dict(specs)['price']['required'], False)

    def test_rejects_bad_input(self):
        bad = ['{', '{}', '[]', json.dumps({'__proto__': {'type':'string'}}),
               json.dumps({'x': {'type': 'object'}}),
               json.dumps({'x': {'type': 'string','selector':'http://evil'}}),
               json.dumps({'x': {'type': 'string','required':'yes'}}),
               json.dumps({'x': {'type': 'string','use_llm': True}}),
               json.dumps({'x': {'type': 'string','hint':'A'*241}}),
               json.dumps({str(i): {'type':'string'} for i in range(17)}),
               json.dumps({'x': {'type':'string','selector':'jsonld:a.b'}}),
               ' '*8193]
        for value in bad:
            with self.subTest(value=value[:35]), self.assertRaises(ValueError):
                parse_schema(value)

    def test_selectors_and_names_are_bounded(self):
        for selector in ('title','description','canonical','lang','h1','headings','links','text','jsonld:price'):
            with self.subTest(selector=selector):
                self.assertEqual(parse_schema(json.dumps({'field_1':{'type':'string','selector':selector}}))['field_1'].selector,selector)
        with self.assertRaises(ValueError):
            parse_schema(json.dumps({'a'*65:{'type':'string'}}))
