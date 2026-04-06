import csv
import tempfile
import unittest

from phishing_pipeline import dns_gate


class DnsGateReliabilityTests(unittest.TestCase):
    def test_resolve_dns_worker_count_respects_explicit_limit(self):
        self.assertEqual(dns_gate._resolve_dns_worker_count(100, max_workers=7), 7)

    def test_write_dns_gate_audit_preserves_failure_reasoning_columns(self):
        rows = [
            {
                "target_url": "https://bad.example",
                "source_workbook": "demo.xlsx",
                "hostname": "bad.example",
                "resolved_ips": "",
                "dns_answer_count": 0,
                "first_resolved_ip": "",
                "asn": "",
                "asn_org": "",
                "country": "",
                "dns_status": "no_records",
                "decision": "rejected",
                "attempts": 1,
                "retry_count": 0,
                "retry_success": False,
                "resolver_profile": "default",
            }
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = f"{temp_dir}\\dns_gate_audit.csv"
            dns_gate.write_dns_gate_audit(rows, output_path=output_path)
            with open(output_path, newline="", encoding="utf-8") as fh:
                written_rows = list(csv.DictReader(fh))

        self.assertEqual(len(written_rows), 1)
        self.assertEqual(written_rows[0]["dns_status"], "no_records")
        self.assertEqual(written_rows[0]["source_workbook"], "demo.xlsx")
        self.assertIn("first_resolved_ip", written_rows[0])
        self.assertIn("asn_org", written_rows[0])


if __name__ == "__main__":
    unittest.main()
