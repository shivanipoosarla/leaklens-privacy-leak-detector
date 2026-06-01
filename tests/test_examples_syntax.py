from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CExampleSyntaxTests(unittest.TestCase):
    def test_c_examples_pass_syntax_check_with_local_klee_stub(self):
        clang = shutil.which("clang")
        if clang is None:
            self.skipTest("clang is not installed")

        for source in sorted((ROOT / "examples").glob("*.c")):
            with self.subTest(source=source.name):
                completed = subprocess.run(
                    [clang, "-fsyntax-only", "-I", str(ROOT / "stubs"), str(source)],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
