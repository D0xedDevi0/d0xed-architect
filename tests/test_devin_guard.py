"""Guard rails: the DEVin package never executes code or touches wallets/x402.

Static source scan of the package itself — proving the scaffold contains no
subprocess/eval/exec surface and imports no wallet/auth/x402 modules, so
submitted repo content can never be executed or reach credentials.
"""
import pathlib
import re
import subprocess
import sys
import unittest

DEVIN_DIR = pathlib.Path(__file__).resolve().parent.parent / "devin"
REPO_ROOT = DEVIN_DIR.parent

FORBIDDEN_PATTERNS = [
    (re.compile(r"\b(import\s+subprocess|from\s+subprocess\s+import|subprocess\.)"),
     "subprocess"),
    (re.compile(r"\beval\s*\("), "eval("),
    (re.compile(r"\bexec\s*\("), "exec("),
    (re.compile(r"os\.system|os\.popen|os\.spawn"), "os command execution"),
    (re.compile(r"shell\s*=\s*True"), "shell=True"),
]

FORBIDDEN_IMPORTS = ["auth", "x402", "vault", "escalate", "contract", "swarm"]


class TestPackageGuard(unittest.TestCase):
    def test_no_execution_surface(self):
        for path in DEVIN_DIR.glob("*.py"):
            src = path.read_text()
            for pat, label in FORBIDDEN_PATTERNS:
                self.assertIsNone(pat.search(src),
                                  f"{path.name} contains forbidden {label}")

    def test_no_wallet_or_payment_imports(self):
        for path in DEVIN_DIR.glob("*.py"):
            src = path.read_text()
            for mod in FORBIDDEN_IMPORTS:
                self.assertNotIn(f"architect.{mod}", src, f"{path.name}")
                self.assertNotIn(f"architect import {mod}", src, f"{path.name}")

    def test_importing_devin_loads_no_credential_modules(self):
        # Run in a FRESH interpreter: in the full suite, other test modules
        # legitimately import architect.auth/x402/etc., so checking sys.modules
        # in-process would be a false positive. Isolated, importing devin must
        # pull in none of the credential/wallet/payment modules.
        forbidden = ("architect.auth", "architect.x402", "architect.vault",
                     "architect.escalate", "architect.contract", "architect.swarm")
        code = (
            "import sys\n"
            "from devin import bot, github_audit, transport  # noqa: F401\n"
            f"print(' '.join(m for m in {forbidden!r} if m in sys.modules))\n"
        )
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, text=True, cwd=str(REPO_ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
