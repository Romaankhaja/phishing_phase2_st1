import tempfile
import unittest
import json
from pathlib import Path
from unittest import mock

import pandas as pd

from phishing_pipeline import pipeline


def _make_output_row(domain: str, label: str) -> dict:
    return {
        "Identified Phishing/Suspected Domain Name": domain,
        "Corresponding CSE Domain Name": "example.com",
        "Hosting IP": "1.2.3.4",
        "Hosting ISP": "Example ISP",
        "Hosting Country": "US",
        "Registrant Name or Registrant Organisation": "Example Org",
        "Registrant Country": "US",
        "Name Servers": "ns1.example.com",
        "Evidence file name": "NA",
        "Source of detection": "hashing",
        "Remarks": "NA",
        "Phishing/Suspected Domains (i.e. Class Label)": label,
    }


class PackageResultsTests(unittest.TestCase):
    def test_resolve_effective_detection_target_ignores_about_blank_redirect(self):
        target = pipeline._resolve_effective_detection_target(
            {
                "Identified Phishing/Suspected Domain Name": "https://example.test/login",
                "final_landing_url": "about:blank",
            }
        )

        self.assertEqual("https://example.test/login", target["effective_url"])
        self.assertEqual("example.test", target["effective_host"])
        self.assertFalse(target["redirect_promoted"])

    def test_package_results_prefers_main_output_to_preserve_legitimate_rows(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root_dir = Path(tmpdir)
            output_dir = root_dir / "output"
            base_dir = root_dir / "phishing_pipeline"
            evidence_dir = root_dir / "evidence"
            output_dir.mkdir()
            base_dir.mkdir()
            evidence_dir.mkdir()

            output_file = output_dir / "output_file.csv"
            filtered_file = output_dir / "output_file_filtered.csv"

            pd.DataFrame(
                [
                    _make_output_row("https://phishing.example", "Phishing"),
                    _make_output_row("https://legitimate.example", "Legitimate"),
                ]
            ).to_csv(output_file, index=False)
            pd.DataFrame(
                [
                    _make_output_row("https://phishing.example", "Phishing"),
                ]
            ).to_csv(filtered_file, index=False)

            with mock.patch.object(pipeline, "ROOT_DIR", str(root_dir)), mock.patch.object(
                pipeline, "BASE_DIR", str(base_dir)
            ), mock.patch.object(pipeline, "EVIDENCE_DIR", str(evidence_dir)):
                zip_path = pipeline.package_results(output_file=str(output_file), zip_path="submission.zip")

            self.assertTrue(Path(zip_path).exists())
            workbook_path = (
                output_dir
                / "PS-02_ISS_NLP_Submission"
                / "PS-02_ISS_NLP_Holdout_Submission_Set.xlsx"
            )
            self.assertTrue(workbook_path.exists())

            packaged_df = pd.read_excel(workbook_path, dtype=str, keep_default_na=False)

            self.assertEqual(len(packaged_df), 2)
            self.assertEqual(
                set(packaged_df["Phishing (Yes)"].tolist()),
                {"Phishing", "Legitimate"},
            )

    def test_package_results_falls_back_to_filtered_when_main_output_is_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root_dir = Path(tmpdir)
            output_dir = root_dir / "output"
            base_dir = root_dir / "phishing_pipeline"
            evidence_dir = root_dir / "evidence"
            output_dir.mkdir()
            base_dir.mkdir()
            evidence_dir.mkdir()

            output_file = output_dir / "output_file.csv"
            filtered_file = output_dir / "output_file_filtered.csv"

            pd.DataFrame(columns=list(_make_output_row("", "").keys())).to_csv(output_file, index=False)
            pd.DataFrame(
                [
                    _make_output_row("https://suspected.example", "Suspected"),
                ]
            ).to_csv(filtered_file, index=False)

            with mock.patch.object(pipeline, "ROOT_DIR", str(root_dir)), mock.patch.object(
                pipeline, "BASE_DIR", str(base_dir)
            ), mock.patch.object(pipeline, "EVIDENCE_DIR", str(evidence_dir)):
                zip_path = pipeline.package_results(output_file=str(output_file), zip_path="submission.zip")

            self.assertTrue(Path(zip_path).exists())
            workbook_path = (
                output_dir
                / "PS-02_ISS_NLP_Submission"
                / "PS-02_ISS_NLP_Holdout_Submission_Set.xlsx"
            )
            packaged_df = pd.read_excel(workbook_path, dtype=str, keep_default_na=False)

            self.assertEqual(len(packaged_df), 1)
            self.assertEqual(packaged_df.loc[0, "Phishing (Yes)"], "Suspected")

    def test_package_results_uses_checkpoint_records_and_scrubs_about_blank(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root_dir = Path(tmpdir)
            output_dir = root_dir / "output"
            base_dir = root_dir / "phishing_pipeline"
            evidence_dir = base_dir / "PS-02_ISS_NLP_Evidences"
            output_dir.mkdir()
            base_dir.mkdir()
            evidence_dir.mkdir()

            output_file = output_dir / "output_file.csv"
            pd.DataFrame(columns=list(_make_output_row("", "").keys())).to_csv(output_file, index=False)

            payload = _make_output_row("about:blank", "Suspected")
            payload["Critical Sector Entity Name"] = "Example CSE"
            payload["Evidence file name"] = "NA"

            checkpoints_file = output_dir / "checkpoints.csv"
            pd.DataFrame(
                [
                    {
                        "record_key": "rk-1",
                        "final_pipeline_status": "completed",
                        "submission_record_json": json.dumps(payload),
                        "raw_url": "https://redirect-example.test",
                        "normalized_url": "https://redirect-example.test",
                    }
                ]
            ).to_csv(checkpoints_file, index=False)

            with mock.patch.object(pipeline, "ROOT_DIR", str(root_dir)), mock.patch.object(
                pipeline, "BASE_DIR", str(base_dir)
            ), mock.patch.object(pipeline, "EVIDENCE_DIR", str(evidence_dir)):
                zip_path = pipeline.package_results(output_file=str(output_file), zip_path="submission.zip")

            self.assertTrue(Path(zip_path).exists())
            workbook_path = (
                output_dir
                / "PS-02_ISS_NLP_Submission"
                / "PS-02_ISS_NLP_Holdout_Submission_Set.xlsx"
            )
            packaged_df = pd.read_excel(workbook_path, dtype=str, keep_default_na=False)

            self.assertEqual(1, len(packaged_df))
            self.assertEqual("https://redirect-example.test", packaged_df.loc[0, "Identified Domain Name"])
            self.assertEqual("Example CSE", packaged_df.loc[0, "Corresponding CSE Name"])


if __name__ == "__main__":
    unittest.main()
