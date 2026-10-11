"""Distribution metadata contracts for a usable CLI/MCP install."""
import pathlib
import tomllib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class PackagingTests(unittest.TestCase):
    def test_cli_dependencies_and_opt_in_extras(self):
        config = tomllib.loads((ROOT / "pyproject.toml").read_text())
        project = config["project"]
        self.assertEqual(project["scripts"]["architect"], "architect.cli:main")
        deps = " ".join(project["dependencies"])
        self.assertIn("eth-account", deps)
        self.assertIn("cryptography", deps)
        self.assertIn("playwright", " ".join(project["optional-dependencies"]["browser"]))
        self.assertIn("mcp", " ".join(project["optional-dependencies"]["mcp"]))
        self.assertEqual(config["tool"]["setuptools"]["packages"], ["architect"])

if __name__ == "__main__":
    unittest.main()
