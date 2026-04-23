import unittest
import json
import zipfile
from pathlib import Path
from unittest import mock

import pandas as pd

from phishing_pipeline import pipeline
from phishing_pipeline import watcher
from phishing_pipeline.reliability import archive_submission_artifacts, build_run_context
from tests._workspace_temp import workspace_tempdir


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
        with workspace_tempdir("package_main") as tmpdir:
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

            with (
                mock.patch.object(pipeline, "ROOT_DIR", str(root_dir)),
                mock.patch.object(pipeline, "BASE_DIR", str(base_dir)),
                mock.patch.object(pipeline, "EVIDENCE_DIR", str(evidence_dir)),
                mock.patch.object(pipeline, "CHECKPOINT_CSV", str(output_dir / "checkpoints.csv")),
            ):
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
        with workspace_tempdir("package_filtered") as tmpdir:
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

            with (
                mock.patch.object(pipeline, "ROOT_DIR", str(root_dir)),
                mock.patch.object(pipeline, "BASE_DIR", str(base_dir)),
                mock.patch.object(pipeline, "EVIDENCE_DIR", str(evidence_dir)),
                mock.patch.object(pipeline, "CHECKPOINT_CSV", str(output_dir / "checkpoints.csv")),
            ):
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
        with workspace_tempdir("package_checkpoints") as tmpdir:
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

            with (
                mock.patch.object(pipeline, "ROOT_DIR", str(root_dir)),
                mock.patch.object(pipeline, "BASE_DIR", str(base_dir)),
                mock.patch.object(pipeline, "EVIDENCE_DIR", str(evidence_dir)),
                mock.patch.object(pipeline, "CHECKPOINT_CSV", str(checkpoints_file)),
            ):
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

    def test_archive_submission_artifacts_copies_root_package_into_run_and_latest(self):
        with workspace_tempdir("package_archive") as tmpdir:
            output_dir = Path(tmpdir) / "output"
            output_dir.mkdir()
            ctx = build_run_context(
                output_dir=str(output_dir),
                run_id="run_test",
                submission_basename="Submission-demo.zip",
            )

            root_zip = output_dir / "Submission-demo.zip"
            with zipfile.ZipFile(root_zip, "w") as zip_fh:
                zip_fh.writestr("PS-02_ISS_NLP_Submission/PS-02_ISS_NLP_Holdout_Submission_Set.xlsx", "demo")

            root_submission_dir = output_dir / "PS-02_ISS_NLP_Submission"
            root_submission_dir.mkdir()
            (root_submission_dir / "PS-02_ISS_NLP_Holdout_Submission_Set.xlsx").write_text("demo", encoding="utf-8")

            archived = archive_submission_artifacts(
                ctx,
                zip_path=str(root_zip),
                submission_dir=str(root_submission_dir),
            )

            self.assertTrue(root_zip.exists())
            self.assertTrue(Path(archived["submission_zip"]).exists())
            self.assertTrue(Path(ctx.artifact_latest_paths["submission_zip"]).exists())
            self.assertTrue(Path(archived["submission_dir"]).exists())
            self.assertTrue((Path(archived["submission_dir"]) / "PS-02_ISS_NLP_Holdout_Submission_Set.xlsx").exists())
            self.assertTrue((Path(ctx.artifact_latest_paths["submission_dir"]) / "PS-02_ISS_NLP_Holdout_Submission_Set.xlsx").exists())

    def test_watcher_moves_expected_submission_zip_from_output_folder(self):
        with workspace_tempdir("watcher_move") as tmpdir:
            project_root = Path(tmpdir)
            package_output_dir = project_root / "output"
            package_output_dir.mkdir()
            watcher_output_dir = project_root / "watcher_out"
            expected_zip = package_output_dir / "Submission-demo-folder.zip"
            expected_zip.write_text("zip", encoding="utf-8")
            older_zip = package_output_dir / "Submission-older.zip"
            older_zip.write_text("older", encoding="utf-8")

            with (
                mock.patch.object(watcher, "PROJECT_ROOT", str(project_root)),
                mock.patch.object(watcher, "OUTPUT_DIR", str(watcher_output_dir)),
            ):
                moved_path = watcher.move_results_to_output("demo-folder")

            self.assertIsNotNone(moved_path)
            self.assertTrue(Path(str(moved_path)).exists())
            self.assertFalse(expected_zip.exists())
            self.assertTrue(Path(str(moved_path)).name.startswith("Submission_demo-folder_"))


if __name__ == "__main__":
    unittest.main()
