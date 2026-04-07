import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ida_pro_mcp import headless_web


class HeadlessWebUiTests(unittest.TestCase):
    def test_workspace_html_includes_code_highlighter_assets(self):
        html = headless_web.WORKSPACE_HTML
        self.assertIn('function renderCodeBlock', html)
        self.assertIn('function highlightCode', html)
        self.assertIn('function jumpToQuery', html)
        self.assertIn('function onCodeBlockClick', html)
        self.assertIn('.syntax-keyword', html)
        self.assertIn('.syntax-mnemonic', html)
        self.assertIn('.syntax-jump', html)
        self.assertIn('data-jump-query', html)
        self.assertIn("onclick='onCodeBlockClick(event)'", html)
        self.assertIn("renderCodeBlock('decompileOutput'", html)
        self.assertIn("renderCodeBlock('disasmOutput'", html)


if __name__ == '__main__':
    unittest.main()
