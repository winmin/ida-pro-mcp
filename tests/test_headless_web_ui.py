import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ida_pro_mcp import headless_web


class HeadlessWebUiTests(unittest.TestCase):
    def test_workspace_html_includes_code_highlighter_assets(self):
        html = headless_web.WORKSPACE_HTML
        js = headless_web.WORKSPACE_JS
        css = headless_web.WORKSPACE_CSS
        self.assertIn("/static/workspace.css", html)
        self.assertIn("/static/workspace.js", html)
        self.assertIn("id='splitter-left'", html)
        self.assertIn("id='splitter-right'", html)
        self.assertIn("id='navBackBtn'", html)
        self.assertIn("id='navForwardBtn'", html)
        self.assertIn("id='hoverPreview'", html)
        self.assertIn("onclick='onCodeBlockClick(event)'", html)
        self.assertIn('function renderCodeBlock', js)
        self.assertIn('function renderCodeLines', js)
        self.assertIn('function highlightCode', js)
        self.assertIn('function jumpToQuery', js)
        self.assertIn('function onCodeBlockClick', js)
        self.assertIn('function initSplitters', js)
        self.assertIn('function loadLayoutPrefs', js)
        self.assertIn('function navigateHistory', js)
        self.assertIn('function restoreNavigationSnapshot', js)
        self.assertIn('function initHoverPreview', js)
        self.assertIn('function fetchPreview', js)
        self.assertIn('data-jump-query', js)
        self.assertIn("renderCodeBlock('decompileOutput'", js)
        self.assertIn("renderCodeBlock('disasmOutput'", js)
        self.assertIn('.splitter', css)
        self.assertIn('.hover-preview', css)
        self.assertIn('.code-line-number', css)
        self.assertIn('.code-line.is-active-address', css)
        self.assertIn('.syntax-keyword', css)
        self.assertIn('.syntax-mnemonic', css)
        self.assertIn('.syntax-jump', css)


if __name__ == '__main__':
    unittest.main()
