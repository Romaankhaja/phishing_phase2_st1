import csv
import json
from datetime import datetime

def analyze_performance():
    metrics_path = r'c:\Users\SATWIK\Documents\Phishing\output\latest\events\stage_metrics.csv'
    events_path = r'c:\Users\SATWIK\Documents\Phishing\output\latest\events\pipeline_stage_events.csv'
    summary_path = r'c:\Users\SATWIK\Documents\Phishing\output\latest\run_summary.json'

    # 1. Overall Timing
    print("--- Overall Timing ---")
    with open(summary_path, 'r') as f:
        summary = json.load(f)
        start = datetime.fromisoformat(summary['started_at'].replace('Z', '+00:00'))
        end = datetime.fromisoformat(summary['completed_at'].replace('Z', '+00:00'))
        duration = end - start
        print(f"Started at: {start}")
        print(f"Completed at: {end}")
        print(f"Total Duration: {duration}")

    # 2. Per-Snapshot Metrics (Resource Usage)
    print("\n--- Resource Snapshot Metrics (Snapshot interval approx 5-10s) ---")
    with open(metrics_path, 'r') as f:
        reader = csv.DictReader(f)
        print(f"{'Time':<25} | {'Stage':<10} | {'CPU Used':<8} | {'Task Backlog':<12}")
        print("-" * 65)
        for row in reader:
            res = json.loads(row['resource_snapshot_json'])
            # Extract backlog from details_json (it varies by stage)
            details = json.loads(row['details_json'])
            backlog = 0
            if 'hash' in details:
                backlog = details['hash'].get('backlog', 0)
            elif 'stage0' in details:
                backlog = details['stage0'].get('remaining', 0)
            
            ts = row['emitted_at']
            print(f"{ts:<25} | {row['stage_name']:<10} | {res.get('used_cpu', 0):<8} | {backlog:<12}")

    # 3. Stage-Wise Event Analysis
    print("\n--- Stage-Wise Event Analysis ---")
    stage_stats = {}
    with open(events_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            stage = row['stage_name']
            if stage not in stage_stats:
                stage_stats[stage] = {'count': 0, 'total_ms': 0}
            
            try:
                ms = int(row['duration_ms'])
            except:
                ms = 0
            
            stage_stats[stage]['count'] += 1
            stage_stats[stage]['total_ms'] += ms

    print(f"{'Stage':<15} | {'Count':<8} | {'Total Time (ms)':<15} | {'Avg Time (ms)':<15}")
    print("-" * 60)
    for stage, stats in stage_stats.items():
        avg = stats['total_ms'] / stats['count'] if stats['count'] > 0 else 0
        print(f"{stage:<15} | {stats['count']:<8} | {stats['total_ms']:<15} | {avg:<15.2f}")

if __name__ == "__main__":
    analyze_performance()
