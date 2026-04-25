import unittest
from pathlib import Path

import pandas as pd
from tests._workspace_temp import workspace_tempdir

from phishing_pipeline import recall_tuning, shortlisting


class SourceWorkbookTaggingTests(unittest.TestCase):
    def test_duplicate_urls_merge_source_workbooks_across_excel_files(self):
        with workspace_tempdir("recall_tuning") as tmpdir:
            tmpdir_path = Path(tmpdir)
            file_a = tmpdir_path / "urls.xlsx"
            file_b = tmpdir_path / "123456.xlsx"

            pd.DataFrame(
                {
                    "domain_name": [
                        "alpha.example",
                        "beta.example",
                    ]
                }
            ).to_excel(file_a, index=False)
            pd.DataFrame(
                {
                    "domain_name": [
                        "alpha.example",
                        "gamma.example",
                    ]
                }
            ).to_excel(file_b, index=False)

            records = shortlisting.load_url_records_from_excel_folder(tmpdir_path)
            record_map = {
                recall_tuning._normalize_stage_url(record["url"]): record["source_workbooks"]
                for record in records
            }

            self.assertEqual(
                sorted(record_map[shortlisting.normalize_url("alpha.example")]),
                ["123456.xlsx", "urls.xlsx"],
            )
            self.assertEqual(
                record_map[shortlisting.normalize_url("beta.example")],
                ["urls.xlsx"],
            )


class RecallTuningHarnessTests(unittest.TestCase):
    def test_copy_tree_contents_skips_nested_tuning_runs(self):
        with workspace_tempdir("recall_summary") as tmpdir:
            tmpdir_path = Path(tmpdir)
            output_dir = tmpdir_path / "output"
            snapshot_dir = tmpdir_path / "snapshot"
            tuning_dir = output_dir / "tuning_runs"
            output_dir.mkdir()
            tuning_dir.mkdir()
            (output_dir / "holdout.csv").write_text("x\n1\n", encoding="utf-8")
            (tuning_dir / "old.txt").write_text("ignore", encoding="utf-8")

            recall_tuning._copy_tree_contents(output_dir, snapshot_dir)

            self.assertTrue((snapshot_dir / "holdout.csv").exists())
            self.assertFalse((snapshot_dir / "tuning_runs").exists())

    def test_summarize_iteration_artifacts_writes_gt_trace_and_workbook_counts(self):
        gt_url = shortlisting.normalize_url("alpha.example")
        gt_targets = [{"gt_domain": "alpha.example", "normalized_url": gt_url}]

        with workspace_tempdir("recall_iteration") as tmpdir:
            iteration_dir = Path(tmpdir)
            pd.DataFrame(
                [
                    {
                        "normalized_url": gt_url,
                        "source_workbook": "123456.xlsx",
                        "reason": "",
                        "survival_path": "score_threshold",
                        "drop_path": "",
                    }
                ]
            ).to_csv(iteration_dir / "stage1_lexical_debug.csv", index=False)
            pd.DataFrame(
                [
                    {
                        "Identified Phishing/Suspected Domain Name": gt_url,
                        "source_workbook": "123456.xlsx",
                        "fetch_status": "timeout",
                        "admission_path": "failed_fetch_strict_lexical_rescue",
                    }
                ]
            ).to_csv(iteration_dir / "holdout.csv", index=False)
            pd.DataFrame(
                [
                    {
                        "url": gt_url,
                        "source_workbook": "123456.xlsx",
                        "classification": "Suspected",
                        "classification_gate_reason": "failed_fetch_strict_lexical_rescue",
                        "review_only_reason": "",
                        "survival_path": "failed_fetch_strict_lexical_rescue",
                        "drop_path": "",
                    }
                ]
            ).to_csv(iteration_dir / "stage3_classification_debug.csv", index=False)
            pd.DataFrame(
                [
                    {
                        "Identified Phishing/Suspected Domain Name": gt_url,
                        "Phishing/Suspected Domains (i.e. Class Label)": "Suspected",
                    }
                ]
            ).to_csv(iteration_dir / "output_file.csv", index=False)
            pd.DataFrame(
                [
                    {
                        "Identified Phishing/Suspected Domain Name": gt_url,
                        "Phishing/Suspected Domains (i.e. Class Label)": "Suspected",
                    }
                ]
            ).to_csv(iteration_dir / "output_file_filtered.csv", index=False)
            pd.DataFrame(
                columns=["Identified Phishing/Suspected Domain Name", "source_workbook", "review_reason"]
            ).to_csv(iteration_dir / "hash_review_queue.csv", index=False)

            summary = recall_tuning.summarize_iteration_artifacts(
                iteration_dir=iteration_dir,
                gt_targets=gt_targets,
                workbook_names=["123456.xlsx", "urls.xlsx"],
            )

            self.assertEqual(summary["gt_final_output_count"], 1)
            self.assertEqual(summary["gt_stage3_count"], 1)
            self.assertEqual(summary["gt_review_count"], 0)
            workbook_counts = pd.read_csv(iteration_dir / "source_workbook_funnel_counts.csv")
            workbook_row = workbook_counts.loc[
                workbook_counts["source_workbook"] == "123456.xlsx"
            ].iloc[0]
            self.assertEqual(int(workbook_row["stage1_count"]), 1)
            self.assertEqual(int(workbook_row["output_count"]), 1)
            gt_trace = pd.read_csv(iteration_dir / "gt_domain_trace.csv")
            self.assertTrue(bool(gt_trace.loc[0, "in_output"]))
            self.assertEqual(
                gt_trace.loc[0, "stage3_gate_reason"],
                "failed_fetch_strict_lexical_rescue",
            )

    def test_rank_iteration_summaries_is_deterministic(self):
        ranked = recall_tuning.rank_iteration_summaries(
            [
                {
                    "iteration_index": 2,
                    "preset_name": "second",
                    "gt_final_output_count": 1,
                    "gt_stage3_count": 2,
                    "gt_review_count": 1,
                    "gt_holdout_count": 1,
                    "flagged_output_count": 3,
                    "total_output_count": 4,
                },
                {
                    "iteration_index": 1,
                    "preset_name": "first",
                    "gt_final_output_count": 1,
                    "gt_stage3_count": 2,
                    "gt_review_count": 1,
                    "gt_holdout_count": 1,
                    "flagged_output_count": 2,
                    "total_output_count": 4,
                },
            ]
        )

        self.assertEqual(ranked[0]["preset_name"], "first")
        self.assertEqual(ranked[0]["rank"], 1)
        self.assertEqual(ranked[1]["rank"], 2)


if __name__ == "__main__":
    unittest.main()
