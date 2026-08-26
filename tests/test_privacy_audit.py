from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/privacy_audit.py"
SPEC = importlib.util.spec_from_file_location("privacy_audit", SCRIPT)
assert SPEC and SPEC.loader
privacy_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(privacy_audit)


class PrivacyAuditTests(unittest.TestCase):
    def test_approved_project_identity(self) -> None:
        self.assertTrue(
            privacy_audit._approved_git_identity(
                "TeshengLee", "55652147+TeshengLee@users.noreply.github.com"
            )
        )

    def test_unrelated_noreply_identity_is_rejected(self) -> None:
        self.assertFalse(
            privacy_audit._approved_git_identity(
                "Maintainers", "maintainers@users.noreply.github.com"
            )
        )


if __name__ == "__main__":
    unittest.main()
