"""Legacy markdown stays byte-identical while typed extraction filters hidden DOM."""
import unittest
from architect.extract import extract, to_markdown

HTML = ('<html><head><title>Alpha</title><meta name="description" content="Desc"></head>'
        '<body><div hidden>Secret</div><h1>A heading</h1><p>Paragraph one</p>'
        '<p style="display:none">Hidden style</p>'
        '<script type="application/ld+json">{"name":"A"}</script></body></html>')
# Captured from HEAD's pre-typed architect/extract.py before adding the typed mode.
LEGACY_MARKDOWN = ('# Alpha\n\n> Desc\n\n## A heading\n\nAlpha\nSecret\n\nA heading\n\n'
                   'Paragraph one\n\nHidden style')

class CompatibilityTests(unittest.TestCase):
    def test_default_markdown_matches_pre_typed_output(self):
        self.assertEqual(to_markdown(extract(HTML, 'https://e.org')), LEGACY_MARKDOWN)

    def test_typed_mode_omits_hidden_content(self):
        page=extract(HTML, 'https://e.org', typed=True)
        self.assertNotIn('Secret',page.text)
        self.assertNotIn('Hidden style',page.text)
        self.assertIn('Paragraph one',page.text)

    def test_aria_hidden_and_void_inside_hidden(self):
        html=('<div aria-hidden="true"><video><source src="a"></video>SECRET</div>'
              '<p>VISIBLE_AFTER</p><span hidden>PRIVATE</span>')
        page=extract(html,'https://e.org',typed=True)
        self.assertNotIn('SECRET',page.text)
        self.assertNotIn('PRIVATE',page.text)
        self.assertIn('VISIBLE_AFTER',page.text)

if __name__ == '__main__': unittest.main()
