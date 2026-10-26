"""Offline checks of the detection rules: python3 -m unittest test_scan"""

import unittest

import scan

PLANTED_TASK = """{"version": "2.0.0", "tasks": [{"label": "eslint-check", "type": "shell",
  "command": "node ./public/fonts/fa-brand-400.woff", "runOptions": {"runOn": "folderOpen"}}]}"""
NORMAL_TASK = """{"version": "2.0.0", "tasks": [{"label": "dev", "type": "shell",
  "command": "npm run dev", "runOptions": {"runOn": "folderOpen"}}]}"""
CLEAN_CONFIG = "import { defineConfig } from 'astro/config';\n\nexport default defineConfig({});\n"
TAMPERED_CONFIG = CLEAN_CONFIG.rstrip("\n") + " " * 400 + "var z = '-829-6';(function(a,b){})\n"
MINIFIED = "export default{a:1,b:2," + "c:3," * 2000 + "}\n"  # long, but no hidden run of spaces


class Detection(unittest.TestCase):
    def test_tasks(self):
        self.assertTrue(scan.task_runs_on_open(PLANTED_TASK))
        self.assertFalse(scan.task_runs_on_open(NORMAL_TASK))

    def test_hidden_code(self):
        self.assertTrue(scan.hidden_code(TAMPERED_CONFIG))
        self.assertTrue(scan.hidden_code("module.exports = {}; global['!'] = '1';"))
        self.assertFalse(scan.hidden_code(CLEAN_CONFIG))
        self.assertFalse(scan.hidden_code(MINIFIED))

    def test_gitignore(self):
        self.assertTrue(scan.gitignore_tampered("__pycache__/\nmodels/\nconfig.bat\n"))
        self.assertFalse(scan.gitignore_tampered(".env\nnode_modules/\n"))

    def test_paths(self):
        self.assertTrue(scan.FAKE_FONT.search("src/a/public/fonts/fa-brand-400.woff"))
        self.assertTrue(scan.FAKE_FONT.search("public/fonts/fa-solid-400.woff2"))
        self.assertFalse(scan.FAKE_FONT.search("public/fonts/fa-brands-400.woff"))  # the real one
        self.assertFalse(scan.FAKE_FONT.search("public/fonts/fa-solid-900.woff2"))
        for path in ("astro.config.mjs", "web/next.config.js", ".eslintrc.js", "server/prisma.config.ts", "api.js"):
            self.assertTrue(scan.CONFIG.search(path), path)
        self.assertFalse(scan.CONFIG.search("src/config.ts"))


if __name__ == "__main__":
    unittest.main()
