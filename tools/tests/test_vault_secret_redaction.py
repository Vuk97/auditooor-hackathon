from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class VaultSecretRedactionTests(unittest.TestCase):
    def test_obsidian_vault_emit_redacts_sk_underscore_tokens(self) -> None:
        mod = _load("obsidian_vault_emit_redaction", ROOT / "tools" / "obsidian-vault-emit.py")
        text = "Solodit key: sk_test_1234567890abcdef1234567890abcdef1234567890"

        redacted, count = mod._redact_text(text)

        self.assertEqual(count, 1)
        self.assertNotIn("sk_test_", redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_memory_deep_crawler_redacts_sk_underscore_tokens(self) -> None:
        mod = _load("memory_deep_crawler_redaction", ROOT / "tools" / "memory-deep-crawler.py")
        text = "Solodit key: sk_test_1234567890abcdef1234567890abcdef1234567890"

        redacted, count = mod._redact(text)

        self.assertEqual(count, 1)
        self.assertNotIn("sk_test_", redacted)
        self.assertIn("[REDACTED]", redacted)


if __name__ == "__main__":
    unittest.main()
