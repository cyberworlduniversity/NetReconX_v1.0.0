"""Regression test: HTTPS certificate verification must remain enabled."""

import ast
import unittest
from pathlib import Path


class TLSVerificationTests(unittest.TestCase):
    def test_no_requests_call_disables_tls_verification(self):
        source = Path(__file__).with_name("netreconx.py").read_text(encoding="utf-8")
        tree = ast.parse(source)
        disabled_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if any(
                    keyword.arg == "verify"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                    for keyword in node.keywords
                ):
                    disabled_calls.append(node.lineno)
        self.assertEqual(disabled_calls, [], "Do not disable HTTPS certificate verification.")


if __name__ == "__main__":
    unittest.main()
