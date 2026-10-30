import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class DetectionToolTests(unittest.TestCase):
    def run_tool(self, *args):
        return subprocess.run([sys.executable, *args], cwd=ROOT,
                              capture_output=True, text=True)

    def test_ai_event_scanner_detects_override_and_canary(self):
        result = self.run_tool("detection/detect_injection.py",
                               "detection/sample_ai_events.jsonl")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("instruction-override", result.stdout)
        self.assertIn("canary-indicator", result.stdout)
        self.assertIn("2 event(s)", result.stdout)

    def test_dns_scanner_finds_synthetic_ai_domains(self):
        result = self.run_tool("detection/shadow_ai_scan.py",
                               "detection/sample_dns.log")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ChatGPT", result.stdout)
        self.assertIn("Claude", result.stdout)
        self.assertIn("indicators only", result.stdout)

if __name__ == "__main__":
    unittest.main()
