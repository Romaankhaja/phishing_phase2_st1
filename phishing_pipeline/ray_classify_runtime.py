from __future__ import annotations

import asyncio
import csv
from dataclasses import asdict
from datetime import datetime
import logging
import os
import socket
import time
from typing import Any
from urllib.parse import urlparse

import pandas as pd

from .config import APPLICATION_ID, ASN_DB_PATH, CITY_DB_PATH, FINAL_OUTPUT, resolve_ray_runtime_config
from .geoip_utils import enrich_with_geoip
from .progress_display import (
    build_compact_postfix,
    build_timing_postfix,
    managed_progress_bar,
    progress_bars_enabled,
    resolve_progress_mode,
    tqdm_logging_redirect,
)
from .reliability import (
    ProgressTracker,
    RunContext,
    get_run_artifact_path,
    make_record_key,
    stage_result_patch,
    sync_run_artifact,
    utc_now_iso,
)
from .ray_runtime import (
    ClassificationRecord,
    _get_ray_primitives,
    _is_debug_mode,
    _log_metrics_periodically,
    _ray_context_dict,
    _ray_get,
    _ray_wait,
    debug_ray_resource_snapshot,
    ensure_ray_initialized,
)

logger = logging.getLogger(__name__)


def _log_ray_classify_decision_inputs(
    row: dict[str, Any],
    *,
    registrar: str,
    hosting_isp: str,
    dns_records: str,
    tvc_brand_spoofed: bool,
    tvc_brand_spoof_strong: bool,
) -> None:
    if not _is_debug_mode():
        return
    logger.info(
        "[RAY-DEBUG] classify inputs | url=%s | fetch_status=%s | strict_lexical=%s | lexical_score_pass=%s | hash_anchor=%s | direct_brand_evidence_count=%s | content_spoof_strong=%s | signal_hit_keywords=%s | signal_hits={domain=%s,favicon=%s,ssl=%s,html=%s,domain_hash=%s} | tvc={spoofed=%s,strong=%s} | registrar=%s | hosting_isp=%s | dns_present=%s",
        str(row.get("Identified Phishing/Suspected Domain Name", "") or row.get("url", "")),
        str(row.get("fetch_status", "") or ""),
        bool(row.get("strict_lexical_hit", False)),
        bool(row.get("lexical_score_pass", False)),
        bool(row.get("hash_anchor", False)),
        int(row.get("direct_brand_evidence_count", 0) or 0),
        bool(row.get("content_spoof_strong", False)),
        bool(row.get("signal_hit_keywords", False)),
        bool(row.get("signal_hit_domain", False)),
        bool(row.get("signal_hit_favicon", False)),
        bool(row.get("signal_hit_ssl_hash", False)),
        bool(row.get("signal_hit_html_hash", False)),
        bool(row.get("signal_hit_domain_hash", False)),
        bool(tvc_brand_spoofed),
        bool(tvc_brand_spoof_strong),
        str(registrar or ""),
        str(hosting_isp or ""),
        bool(str(dns_records or "").strip() and str(dns_records or "").strip().upper() != "NA"),
    )


def _build_classify_progress_postfix(
    *,
    progress_tracker: ProgressTracker,
    started_monotonic: float,
    inflight: int,
    flagged: int,
    review: int,
    failed: int,
    ocr_stats: dict[str, Any] | None,
    classify_actor_count: int,
) -> dict[str, str]:
    fields = build_timing_postfix(
        completed=progress_tracker.completed,
        total=progress_tracker.total,
        started_monotonic=started_monotonic,
        rate_key="rows/s",
    )
    stats = dict(ocr_stats or {})
    fields.update(
        {
            "inflight": int(inflight),
            "flagged": int(flagged),
            "review": int(review),
            "failed": int(failed),
            "ocr_q": int(stats.get("queue_depth", 0) or 0),
            "ocr_batch": int(stats.get("last_batch_size", 0) or 0),
            "ocr_batches": int(stats.get("batches_processed", 0) or 0),
            "classify_actors": int(classify_actor_count),
        }
    )
    return build_compact_postfix(fields)


_INFRA_EMPTY_VALUES = {"", "na", "n/a", "none", "null", "nan"}


def _normalize_infra_text(value: Any) -> str:
    if value is None:
        return "NA"
    try:
        if pd.isna(value):
            return "NA"
    except Exception:
        pass
    text = str(value).strip()
    if not text or text.lower() in _INFRA_EMPTY_VALUES:
        return "NA"
    return text


def _first_row_infra_value(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        if key not in row:
            continue
        value = _normalize_infra_text(row.get(key))
        if value != "NA":
            return value
    return "NA"


def _resolve_row_infrastructure_seed(row: dict[str, Any]) -> dict[str, str]:
    return {
        "reg_date": _first_row_infra_value(row, "reg_date", "Domain Registration Date"),
        "registrar": _first_row_infra_value(row, "registrar", "Registrar Name"),
        "registrant_name": _first_row_infra_value(
            row,
            "registrant_name",
            "Registrant Name or Registrant Organisation",
        ),
        "registrant_country": _first_row_infra_value(row, "registrant_country", "Registrant Country"),
        "name_servers": _first_row_infra_value(row, "name_servers", "Name Servers"),
        "ip": _first_row_infra_value(row, "hosting_ip", "Hosting IP", "ip_address", "resolved_ip"),
        "hosting_isp": _first_row_infra_value(row, "hosting_isp", "Hosting ISP"),
        "hosting_country": _first_row_infra_value(row, "hosting_country", "Hosting Country"),
        "dns_records": _first_row_infra_value(row, "dns_records", "DNS Records (if any)"),
        "registration_lookup_status": _first_row_infra_value(row, "registration_lookup_status"),
    }


def _aggregate_ocr_stats(stats_rows: list[dict[str, Any]] | None) -> dict[str, Any]:
    aggregate = {
        "ready": True,
        "queue_depth": 0,
        "batches_processed": 0,
        "items_processed": 0,
        "last_batch_size": 0,
    }
    for stats in list(stats_rows or []):
        aggregate["ready"] = bool(aggregate["ready"]) and bool(stats.get("ready", False))
        aggregate["queue_depth"] += int(stats.get("queue_depth", 0) or 0)
        aggregate["batches_processed"] += int(stats.get("batches_processed", 0) or 0)
        aggregate["items_processed"] += int(stats.get("items_processed", 0) or 0)
        aggregate["last_batch_size"] += int(stats.get("last_batch_size", 0) or 0)
    return aggregate


def _append_debug_rows_csv(
    *,
    rows: list[dict[str, Any]],
    output_path: str,
    run_context: RunContext | None,
    artifact_key: str,
) -> None:
    if not rows:
        return
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    fieldnames: list[str] = []
    if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
        with open(output_path, newline="", encoding="utf-8") as fh:
            fieldnames = list(next(csv.reader(fh), []))
    if not fieldnames:
        seen: set[str] = set()
        for row in rows:
            for key in row.keys():
                column = str(key)
                if column and column not in seen:
                    seen.add(column)
                    fieldnames.append(column)
    if not fieldnames:
        return
    write_header = not os.path.exists(output_path) or os.path.getsize(output_path) == 0
    with open(output_path, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        if write_header:
            writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in fieldnames})
    sync_run_artifact(run_context, artifact_key, src_path=output_path, best_effort=True)


async def classify_hash_only_row_impl(
    *,
    row: dict[str, Any],
    sequence_number: int,
    client: Any,
    brand_model: Any,
    domain_model: Any,
    brand_classes: list[str],
    source_classes: list[str],
    feature_cols: list[str],
    scaler: Any,
    imputer: Any,
    failed_fetch_suspected_min: float | None,
    failed_fetch_review_min: float | None,
    ocr_worker: Any,
    whois_actor: Any,
    infrastructure_cache: dict[str, Any] | None = None,
) -> dict[str, Any]:
    import dns.resolver
    import tldextract
    import whois

    from . import pipeline as pipeline_module
    from .utils import extract_network_features_async

    eligible_fetch_statuses = {"fetched", "fetched_visual_missing"}
    target_info = pipeline_module._resolve_effective_detection_target(row)
    input_domain_url = str(target_info["original_url"] or row.get("Identified Phishing/Suspected Domain Name", "") or "").strip()
    domain_url = str(target_info["effective_url"] or input_domain_url).strip()
    normalized_url = input_domain_url.strip().lower()
    host = str(target_info["effective_host"] or (urlparse(domain_url).hostname or domain_url)).split(":")[0]
    screenshot_path = str(row.get("screenshot_path", "") or "").strip()
    fetch_status = str(row.get("fetch_status", "fetched") or "fetched").strip().lower()
    source_workbook = str(row.get("source_workbook", "") or "")
    confidence_band = row.get("confidence_band", "Low")
    evidence_tier = pipeline_module._normalize_evidence_tier(row)
    stage_started_at = utc_now_iso()
    stage_started_monotonic = time.perf_counter()
    registration_only_enrichment = pipeline_module._requires_registration_only_enrichment(row)
    infrastructure_cache = dict(infrastructure_cache or {})
    resolved_ip_cache = infrastructure_cache.setdefault("resolved_ip_by_host", {})
    rdap_cache = infrastructure_cache.setdefault("rdap_by_host", {})
    whois_cache = infrastructure_cache.setdefault("whois_by_host", {})
    dns_cache = infrastructure_cache.setdefault("dns_by_host", {})
    geoip_cache = infrastructure_cache.setdefault("geoip_by_ip", {})
    row_infra = _resolve_row_infrastructure_seed(row)
    model_needs_network_features = bool(feature_cols and scaler is not None and imputer is not None)

    def _event(status: str, *, error_type: str = "", error_message: str = "") -> dict[str, Any]:
        return {
            "run_id": "",
            "record_key": make_record_key(normalized_url, source_workbook),
            "source_workbook": source_workbook,
            "normalized_url": normalized_url,
            "stage_name": "classify",
            "attempt_index": 1,
            "worker_id": "ray-classify",
            "started_at": stage_started_at,
            "finished_at": utc_now_iso(),
            "duration_ms": int(max(0.0, (time.perf_counter() - stage_started_monotonic) * 1000.0)),
            "status": status,
            "error_type": error_type,
            "error_message": error_message,
            "retry_count": 0,
            "timeout_flag": 0,
            "fallback_taken": "",
        }

    def _patch(
        *,
        stage_status: str,
        final_pipeline_status: str | None = None,
        final_decision: str | None = None,
        failure_reason: str | None = None,
        submission_record: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return stage_result_patch(
            run_id="",
            raw_url=input_domain_url,
            normalized_url=normalized_url,
            source_workbook=source_workbook,
            stage_name="classify",
            stage_status=stage_status,
            current_stage="classify",
            worker_id="ray-classify",
            final_pipeline_status=final_pipeline_status,
            final_decision=final_decision,
            failure_reason=failure_reason,
            submission_record=submission_record,
        )

    def _record(classification: str, *, source_of_detection: str, reg_date: str, registrar: str, registrant_name: str, registrant_country: str, name_servers: str, ip: str, hosting_isp: str, hosting_country: str, dns_records: str, evidence_name: str, remarks: str) -> dict[str, Any]:
        return {
            "Application_ID": APPLICATION_ID,
            "Source of detection": source_of_detection,
            "Identified Phishing/Suspected Domain Name": domain_url,
            "Corresponding CSE Domain Name": row.get("Legitimate Domains", ""),
            "Critical Sector Entity Name": row.get("Cooresponding CSE", ""),
            "Phishing/Suspected Domains (i.e. Class Label)": classification,
            "Domain Registration Date": reg_date,
            "Registrar Name": registrar,
            "Registrant Name or Registrant Organisation": registrant_name,
            "Registrant Country": registrant_country,
            "Name Servers": name_servers,
            "Hosting IP": ip,
            "Hosting ISP": hosting_isp,
            "Hosting Country": hosting_country,
            "DNS Records (if any)": dns_records,
            "Evidence file name": evidence_name,
            "Date of detection (DD-MM-YYYY)": datetime.now().strftime("%d-%m-%Y"),
            "Time of detection (HH-MM-SS)": datetime.now().strftime("%H:%M:%S"),
            "Date of Post (If detection is from Source: social media)": "NA",
            "Remarks": remarks,
        }

    if fetch_status not in eligible_fetch_statuses and not registration_only_enrichment:
        _log_ray_classify_decision_inputs(
            row,
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
            tvc_brand_spoofed=False,
            tvc_brand_spoof_strong=False,
        )
        decision = pipeline_module._hybrid_hash_decision(
            row,
            registrar="NA",
            hosting_isp="NA",
            dns_records="NA",
            ocr_text_from_csv="",
            tvc_brand_spoofed=False,
            tvc_brand_spoof_strong=False,
            brand_model_agrees=False,
            domain_model_agrees=False,
            brand_model_confidence=0.0,
            domain_model_confidence=0.0,
            failed_fetch_suspected_min=failed_fetch_suspected_min,
            failed_fetch_review_min=failed_fetch_review_min,
        )
        classification = str(decision.get("classification", "Legitimate"))
        emit_output = bool(decision.get("emit_output", False))
        classification_gate_reason = str(decision.get("classification_gate_reason", "") or "")
        review_only_reason = str(decision.get("review_only_reason", "") or "")
        corroboration = int(decision.get("non_lexical_corroboration_count", 0) or 0)
        flagged_output = bool(emit_output and classification in {"Phishing", "Suspected"})
        review_sink = bool(classification in {"Legitimate", "REVIEW_ONLY"})
        output_record = None
        if flagged_output:
            output_record = _record(
                classification,
                source_of_detection=pipeline_module.adjust_source(row.get("Cooresponding CSE", ""), row.get("Legitimate Domains", ""), "Unknown"),
                reg_date="NA",
                registrar="NA",
                registrant_name="NA",
                registrant_country="NA",
                name_servers="NA",
                ip="NA",
                hosting_isp="NA",
                hosting_country="NA",
                dns_records="NA",
                evidence_name="NA",
                remarks=pipeline_module._build_output_remarks(
                    row=row,
                    classification=classification,
                    evidence_tier=evidence_tier,
                    hosting_ip="NA",
                ),
            )
        review_row = None
        if review_sink:
            review_row = dict(row)
            review_row.update(
                {
                    "review_reason": review_only_reason or classification_gate_reason or "stage3_review_only",
                    "final_classification": classification,
                    "classification_gate_reason": classification_gate_reason,
                    "non_lexical_corroboration_count": corroboration,
                    "tvc_match_surface": "none",
                    "tvc_matched_alias": "",
                    "tvc_spoof_strong": False,
                    "registrar": "NA",
                    "hosting_isp": "NA",
                    "hosting_country": "NA",
                    "dns_records": "NA",
                }
            )
        model_feature_status = (
            "skipped_non_fetched_fetch_evidence_unavailable"
            if classification_gate_reason == "strict_lexical_fetch_evidence_unavailable_suspected"
            else "skipped_non_fetched_fetch_state"
        )
        return asdict(
            ClassificationRecord(
                output_record=output_record,
                review_row=review_row,
                stage2_debug_row={
                    "url": domain_url,
                    "source_workbook": source_workbook,
                    "shortlisted_cse": row.get("Cooresponding CSE", ""),
                    "shortlisted_domain": row.get("Legitimate Domains", ""),
                    "fetch_status": fetch_status,
                    "final_landing_url": row.get("final_landing_url", ""),
                    "parking_provider": row.get("parking_provider", ""),
                    "parking_reason": row.get("parking_reason", ""),
                    "brand_model_top1": "NA",
                    "brand_model_confidence": 0.0,
                    "domain_model_top1": "Unknown",
                    "domain_model_confidence": 0.0,
                    "model_brand_agrees_with_shortlist": False,
                    "model_domain_agrees_with_shortlist": False,
                    "model_feature_status": model_feature_status,
                    "model_input_error": classification_gate_reason or fetch_status,
                    "model_usable": False,
                    "decision_code": model_feature_status,
                    "reason_code": classification_gate_reason or fetch_status,
                    **pipeline_module._stage1_debug_compat_payload(row),
                },
                stage3_debug_row={
                    "url": domain_url,
                    "source_workbook": source_workbook,
                    "shortlisted_cse": row.get("Cooresponding CSE", ""),
                    "shortlisted_domain": row.get("Legitimate Domains", ""),
                    "fetch_status": fetch_status,
                    "final_landing_url": row.get("final_landing_url", ""),
                    "parking_provider": row.get("parking_provider", ""),
                    "parking_reason": row.get("parking_reason", ""),
                    "placeholder_or_parking_reason": row.get("placeholder_or_parking_reason", row.get("parking_reason", "")),
                    "classification": classification,
                    "confidence_band": confidence_band,
                    "evidence_tier": evidence_tier,
                    "lexical_score": row.get("lexical_score", 0.0),
                    "hash_score": row.get("hash_score", 0.0),
                    "old_fuzzy_hit": row.get("old_fuzzy_hit", False),
                    "hybrid_lexical_hit": row.get("hybrid_lexical_hit", False),
                    "strict_lexical_hit": row.get("strict_lexical_hit", False),
                    "lexical_score_pass": row.get("lexical_score_pass", False),
                    "fallback_rank_only": row.get("fallback_rank_only", False),
                    "typo_anchor": row.get("typo_anchor", False),
                    "hash_anchor": row.get("hash_anchor", False),
                    "generic_token_only_match": row.get("generic_token_only_match", False),
                    "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                    "stage1_passthrough": row.get("stage1_passthrough", False),
                    "tvc_brand_detected": False,
                    "tvc_detected_brand": "none",
                    "tvc_brand_spoofed": False,
                    "tvc_match_surface": "none",
                    "tvc_matched_alias": "",
                    "tvc_spoof_strong": False,
                    "ocr_text_len": 0,
                    "registrar": "NA",
                    "hosting_isp": "NA",
                    "hosting_country": "NA",
                    "dns_records": "NA",
                    "brand_model_top1": "NA",
                    "brand_model_confidence": 0.0,
                    "domain_model_top1": "Unknown",
                    "domain_model_confidence": 0.0,
                    "model_brand_agrees_with_shortlist": False,
                    "model_domain_agrees_with_shortlist": False,
                    "model_feature_status": model_feature_status,
                    "model_input_error": classification_gate_reason or fetch_status,
                    "model_usable": False,
                    "decision_code": classification_gate_reason or classification or fetch_status,
                    "reason_code": review_only_reason or classification_gate_reason or fetch_status,
                    "classification_gate_reason": classification_gate_reason,
                    "review_only_reason": review_only_reason,
                    "survival_path": classification_gate_reason if (flagged_output or review_sink) else "",
                    "drop_path": "" if (flagged_output or review_sink) else classification_gate_reason,
                    "non_lexical_corroboration_count": corroboration,
                    **pipeline_module._stage1_debug_compat_payload(row),
                },
                checkpoint_patch=_patch(stage_status=classification_gate_reason or "non_fetched", final_pipeline_status="completed" if flagged_output else "review_only" if review_sink else "classification_failed", final_decision=classification if (flagged_output or review_sink) else "UNCLASSIFIED", failure_reason=review_only_reason or classification_gate_reason or fetch_status, submission_record=output_record if flagged_output else None),
                stage_event=_event(classification_gate_reason or "non_fetched"),
                classification=classification,
                flagged_output=flagged_output,
                review_sink=review_sink,
            )
        )

    from . import pipeline as pipeline_module

    html_brand_text = " ".join(
        part
        for part in [
            str(row.get("html_title_text", "") or "").strip(),
            str(row.get("visible_text_excerpt", "") or "").strip(),
        ]
        if part
    )
    ocr_request = {
        "domain_url": domain_url,
        "screenshot_path": screenshot_path,
        "shortlisted_cse": str(row.get("Cooresponding CSE", "") or ""),
        "shortlisted_domain": str(row.get("Legitimate Domains", "") or ""),
        "html_text": html_brand_text,
    }
    ocr_tvc = (
        await _ray_get(ocr_worker.extract.remote(ocr_request))
        if ocr_worker is not None
        else await pipeline_module._extract_hash_only_ocr_tvc(**ocr_request)
    )
    if registration_only_enrichment:
        net_feats = {}
    elif model_needs_network_features:
        try:
            net_feats = await extract_network_features_async(domain_url)
        except Exception:
            net_feats = {}
    else:
        net_feats = {}
    brand_model_top1 = "NA"
    brand_model_confidence = 0.0
    domain_model_top1 = "Unknown"
    domain_model_confidence = 0.0
    model_brand_agrees_with_shortlist = False
    model_domain_agrees_with_shortlist = False
    model_feature_status = "model_unavailable"
    model_input_error = ""
    model_usable = False

    resolved_ip = None
    seed_ip = _normalize_infra_text(row_infra.get("ip"))
    if seed_ip != "NA":
        resolved_ip = seed_ip
    elif str(net_feats.get("ip_address") or "").strip():
        resolved_ip = str(net_feats.get("ip_address") or "").strip()
    elif str(resolved_ip_cache.get(host, "") or "").strip():
        resolved_ip = str(resolved_ip_cache.get(host, "") or "").strip()
    if resolved_ip is not None and host:
        resolved_ip_cache[host] = resolved_ip
    if resolved_ip is None and not registration_only_enrichment:
        try:
            loop = asyncio.get_running_loop()
            resolved_ip = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyname, host), timeout=3.0)
            if resolved_ip and host:
                resolved_ip_cache[host] = str(resolved_ip)
        except Exception:
            pass

    def _get_rdap_url(domain_host: str) -> str:
        ext = tldextract.extract(domain_host)
        tld = ext.suffix.split(".")[-1] if ext.suffix else ""
        return pipeline_module.RDAP_DIRECT_URLS.get(tld, pipeline_module.RDAP_FALLBACK_URL)

    reg_data = None
    registration_lookup_status = str(row_infra.get("registration_lookup_status", "") or "").strip().lower()
    if registration_lookup_status in {"", "na", "n/a", "none", "null", "nan"}:
        registration_lookup_status = "unknown"
    if any(row_infra.get(field, "NA") != "NA" for field in ("reg_date", "registrar", "registrant_name", "registrant_country", "name_servers")):
        reg_data = {
            "reg_date": row_infra.get("reg_date", "NA"),
            "registrar": row_infra.get("registrar", "NA"),
            "registrant_name": row_infra.get("registrant_name", "NA"),
            "registrant_country": row_infra.get("registrant_country", "NA"),
            "name_servers": row_infra.get("name_servers", "NA"),
        }
        if registration_lookup_status == "unknown":
            registration_lookup_status = "reused_from_row"
    elif registration_lookup_status == "not_registered":
        reg_data = None
    elif host in rdap_cache:
        cached_rdap = dict(rdap_cache.get(host) or {})
        reg_data = dict(cached_rdap.get("reg_data") or {}) or None
        registration_lookup_status = str(cached_rdap.get("status") or "unknown")
    else:
        try:
            resp = await client.get(f"{_get_rdap_url(host)}{host}")
            if resp.status_code == 200:
                reg_data = pipeline_module._parse_rdap_to_fields(resp.json())
                registration_lookup_status = "registered"
            elif resp.status_code == 404:
                registration_lookup_status = "not_registered"
            else:
                registration_lookup_status = f"rdap_http_{resp.status_code}"
        except Exception:
            pass
        if host:
            rdap_cache[host] = {
                "status": registration_lookup_status,
                "reg_data": dict(reg_data) if isinstance(reg_data, dict) else None,
            }

    if registration_lookup_status == "not_registered":
        output_record = _record(
            "Suspected",
            source_of_detection=pipeline_module.adjust_source(row.get("Cooresponding CSE", ""), row.get("Legitimate Domains", ""), "Unknown"),
            reg_date="NA",
            registrar="NA",
            registrant_name="NA",
            registrant_country="NA",
            name_servers="NA",
            ip="NA",
            hosting_isp="NA",
            hosting_country="NA",
            dns_records="NA",
            evidence_name="NA",
            remarks=pipeline_module._build_output_remarks(
                row=row,
                classification="Suspected",
                evidence_tier=evidence_tier,
                hosting_ip="NA",
            ),
        )
        return asdict(
            ClassificationRecord(
                output_record=output_record,
                review_row=None,
                stage2_debug_row={
                    "url": domain_url,
                    "source_workbook": source_workbook,
                    "shortlisted_cse": row.get("Cooresponding CSE", ""),
                    "shortlisted_domain": row.get("Legitimate Domains", ""),
                    "fetch_status": fetch_status,
                    "final_landing_url": row.get("final_landing_url", ""),
                    "parking_provider": row.get("parking_provider", ""),
                    "parking_reason": row.get("parking_reason", ""),
                    "brand_model_top1": "NA",
                    "brand_model_confidence": 0.0,
                    "domain_model_top1": "Unknown",
                    "domain_model_confidence": 0.0,
                    "model_brand_agrees_with_shortlist": False,
                    "model_domain_agrees_with_shortlist": False,
                    "model_feature_status": "skipped_not_registered_domain",
                    "model_input_error": "rdap_not_found",
                    "model_usable": False,
                    "decision_code": "skipped_not_registered_domain",
                    "reason_code": "rdap_not_found",
                    **pipeline_module._stage1_debug_compat_payload(row),
                },
                stage3_debug_row={
                    "url": domain_url,
                    "source_workbook": source_workbook,
                    "shortlisted_cse": row.get("Cooresponding CSE", ""),
                    "shortlisted_domain": row.get("Legitimate Domains", ""),
                    "fetch_status": fetch_status,
                    "final_landing_url": row.get("final_landing_url", ""),
                    "parking_provider": row.get("parking_provider", ""),
                    "parking_reason": row.get("parking_reason", ""),
                    "placeholder_or_parking_reason": row.get("placeholder_or_parking_reason", ""),
                    "classification": "Suspected",
                    "confidence_band": confidence_band,
                    "evidence_tier": evidence_tier,
                    "lexical_score": row.get("lexical_score", 0.0),
                    "hash_score": row.get("hash_score", 0.0),
                    "old_fuzzy_hit": row.get("old_fuzzy_hit", False),
                    "hybrid_lexical_hit": row.get("hybrid_lexical_hit", False),
                    "strict_lexical_hit": row.get("strict_lexical_hit", False),
                    "lexical_score_pass": row.get("lexical_score_pass", False),
                    "fallback_rank_only": row.get("fallback_rank_only", False),
                    "typo_anchor": row.get("typo_anchor", False),
                    "hash_anchor": row.get("hash_anchor", False),
                    "generic_token_only_match": row.get("generic_token_only_match", False),
                    "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                    "stage1_passthrough": row.get("stage1_passthrough", False),
                    "tvc_brand_detected": False,
                    "tvc_detected_brand": "none",
                    "tvc_brand_spoofed": False,
                    "tvc_match_surface": "none",
                    "tvc_matched_alias": "",
                    "tvc_spoof_strong": False,
                    "ocr_text_len": 0,
                    "registrar": "NA",
                    "hosting_isp": "NA",
                    "hosting_country": "NA",
                    "dns_records": "NA",
                    "brand_model_top1": "NA",
                    "brand_model_confidence": 0.0,
                    "domain_model_top1": "Unknown",
                    "domain_model_confidence": 0.0,
                    "model_brand_agrees_with_shortlist": False,
                    "model_domain_agrees_with_shortlist": False,
                    "model_feature_status": "skipped_not_registered_domain",
                    "model_input_error": "rdap_not_found",
                    "model_usable": False,
                    "decision_code": "not_registered_domain_suspected",
                    "reason_code": "not_registered_domain_suspected",
                    "classification_gate_reason": "not_registered_domain_suspected",
                    "review_only_reason": "",
                    "survival_path": "not_registered_domain",
                    "drop_path": "",
                    "non_lexical_corroboration_count": 1,
                    **pipeline_module._stage1_debug_compat_payload(row),
                },
                checkpoint_patch=_patch(stage_status="not_registered_domain", final_pipeline_status="completed", final_decision="Suspected", failure_reason="not_registered_domain_suspected", submission_record=output_record),
                stage_event=_event("not_registered_domain"),
                classification="Suspected",
                flagged_output=True,
                review_sink=False,
            )
        )

    if reg_data is None and (resolved_ip is not None or registration_only_enrichment):
        if host in whois_cache:
            reg_data = dict(whois_cache.get(host) or {}) or None
        else:
            if whois_actor is not None:
                await _ray_get(whois_actor.acquire.remote())
            try:
                loop = asyncio.get_running_loop()
                w = await asyncio.wait_for(loop.run_in_executor(None, whois.whois, host), timeout=5.0)
                if w:
                    creation_date = w.creation_date[0] if isinstance(w.creation_date, list) and w.creation_date else w.creation_date
                    reg_data = {
                        "reg_date": str(creation_date) if creation_date else "NA",
                        "registrar": w.registrar or "NA",
                        "registrant_name": w.name or w.org or getattr(w, "registrant_name", None) or "NA",
                        "registrant_country": w.country or "NA",
                        "name_servers": ";".join(str(ns) for ns in w.name_servers) if w.name_servers else "NA",
                    }
                if host:
                    whois_cache[host] = dict(reg_data) if isinstance(reg_data, dict) else {}
            except Exception:
                if host:
                    whois_cache[host] = {}

    dns_records = row_infra.get("dns_records", "NA")
    if dns_records == "NA" and resolved_ip is not None:
        if host in dns_cache:
            dns_records = str(dns_cache.get(host) or "NA")
        else:
            try:
                loop = asyncio.get_running_loop()

                def _resolve_sync() -> str:
                    values: list[str] = []
                    for qtype in ("A", "NS", "MX", "CNAME"):
                        try:
                            answers = dns.resolver.resolve(host, qtype, lifetime=2.0)
                            values.extend(f"{qtype}:{answer.to_text()}" for answer in answers)
                        except Exception:
                            continue
                    return ";".join(values) if values else "NA"

                dns_records = await loop.run_in_executor(None, _resolve_sync)
            except Exception:
                dns_records = "NA"
            if host:
                dns_cache[host] = dns_records

    rd = reg_data or {}
    reg_date = rd.get("reg_date", "NA")
    registrar = rd.get("registrar", "NA")
    registrant_name = rd.get("registrant_name", "NA")
    registrant_country = rd.get("registrant_country", "NA")
    name_servers = rd.get("name_servers", "NA")
    geo_dict: dict[str, Any] = {"ip_address": resolved_ip or "NA"}
    ip = row_infra.get("ip", "NA")
    if ip == "NA" and resolved_ip is not None:
        ip = str(resolved_ip)
    hosting_isp = row_infra.get("hosting_isp", "NA")
    hosting_country = row_infra.get("hosting_country", "NA")
    geo_cache_key = _normalize_infra_text(resolved_ip or ip or "")
    if geo_cache_key == "NA":
        geo_cache_key = ""
    if geo_cache_key and geo_cache_key in geoip_cache:
        cached_geo = dict(geoip_cache.get(geo_cache_key) or {})
        geo_dict.update(cached_geo)
    elif geo_cache_key and (ip == "NA" or hosting_isp == "NA" or hosting_country == "NA"):
        geo_input = pd.DataFrame([{"url": domain_url, "ip_address": resolved_ip or ip or "NA"}])
        cached_geo = enrich_with_geoip(geo_input, ASN_DB_PATH, CITY_DB_PATH).iloc[0].to_dict()
        geoip_cache[geo_cache_key] = dict(cached_geo)
        geo_dict.update(cached_geo)
    if ip == "NA":
        ip = str(geo_dict.get("ip_address") or (resolved_ip or "NA"))
    if hosting_isp == "NA":
        hosting_isp = str(geo_dict.get("asn_org", "NA")) if geo_dict.get("asn_org") and not pd.isna(geo_dict.get("asn_org")) else "NA"
    if hosting_country == "NA":
        hosting_country = str(geo_dict.get("country", "NA")) if geo_dict.get("country") and not pd.isna(geo_dict.get("country")) else "NA"
    if model_needs_network_features:
        try:
            x_frame = pipeline_module._build_hash_only_model_frame(row, net_feats, geo_dict, imputer)
            x_imp = imputer.transform(x_frame)
            x_sc = scaler.transform(x_imp)
            brand_model_top1, brand_model_confidence = pipeline_module._safe_predict_top1(brand_model, x_sc, brand_classes)
            domain_model_top1, domain_model_confidence = pipeline_module._safe_predict_top1(domain_model, x_sc, source_classes)
            shortlisted_cse = str(row.get("Cooresponding CSE", "") or "").strip().lower()
            shortlisted_domain = str(row.get("Legitimate Domains", "") or "").strip().lower()
            model_brand_agrees_with_shortlist = brand_model_top1 != "NA" and shortlisted_cse and str(brand_model_top1).strip().lower() == shortlisted_cse
            model_domain_agrees_with_shortlist = domain_model_top1 not in {"NA", "Unknown"} and shortlisted_domain and str(domain_model_top1).strip().lower() == shortlisted_domain
            model_feature_status = "ok"
            model_usable = True
        except Exception as exc:
            model_feature_status = "feature_error"
            model_input_error = str(exc)

    _log_ray_classify_decision_inputs(
        row,
        registrar=registrar,
        hosting_isp=hosting_isp,
        dns_records=dns_records,
        tvc_brand_spoofed=bool(ocr_tvc.get("tvc_brand_spoofed", False)),
        tvc_brand_spoof_strong=bool(ocr_tvc.get("tvc_spoof_strong", False)),
    )
    decision = pipeline_module._hybrid_hash_decision(
        row,
        registrar=registrar,
        hosting_isp=hosting_isp,
        dns_records=dns_records,
        ocr_text_from_csv=ocr_tvc.get("ocr_text", ""),
        tvc_brand_spoofed=bool(ocr_tvc.get("tvc_brand_spoofed", False)),
        tvc_brand_spoof_strong=bool(ocr_tvc.get("tvc_spoof_strong", False)),
        brand_model_agrees=model_brand_agrees_with_shortlist,
        domain_model_agrees=model_domain_agrees_with_shortlist,
        brand_model_confidence=brand_model_confidence,
        domain_model_confidence=domain_model_confidence,
        failed_fetch_suspected_min=failed_fetch_suspected_min,
        failed_fetch_review_min=failed_fetch_review_min,
        hosting_ip=ip,
        hosting_country=hosting_country,
        registrant_name=registrant_name,
        registrant_country=registrant_country,
        name_servers=name_servers,
        registration_lookup_status=registration_lookup_status,
    )
    classification = str(decision.get("classification", "Legitimate"))
    emit_output = bool(decision.get("emit_output", False))
    classification_gate_reason = str(decision.get("classification_gate_reason", "") or "")
    review_only_reason = str(decision.get("review_only_reason", "") or "")
    corroboration = int(decision.get("non_lexical_corroboration_count", 0) or 0)
    flagged_output = bool(emit_output and classification in {"Phishing", "Suspected"})
    review_sink = bool(classification in {"Legitimate", "REVIEW_ONLY"})
    source_of_detection = pipeline_module.adjust_source(
        row.get("Cooresponding CSE", ""),
        row.get("Legitimate Domains", ""),
        domain_model_top1 if domain_model_top1 not in {"NA", ""} else "Unknown",
    )
    evidence_name = "NA"
    if flagged_output and classification.lower() == "phishing":
        evidence_path, evidence_name = pipeline_module.format_evidence_filename(
            row.get("Cooresponding CSE", "Unknown"),
            domain_url,
            sequence_number,
            application_id=APPLICATION_ID,
        )
        await asyncio.to_thread(pipeline_module.move_screenshot_to_evidence_from_path, screenshot_path, evidence_path)

    output_record = _record(
        classification,
        source_of_detection=source_of_detection,
        reg_date=reg_date,
        registrar=registrar,
        registrant_name=registrant_name,
        registrant_country=registrant_country,
        name_servers=name_servers,
        ip=ip,
        hosting_isp=hosting_isp,
        hosting_country=hosting_country,
        dns_records=dns_records,
        evidence_name=evidence_name,
        remarks=pipeline_module._build_output_remarks(
            row=row,
            classification=classification,
            evidence_tier=evidence_tier,
            hosting_ip=ip,
        ),
    )
    review_row = None
    if review_sink:
        review_row = dict(row)
        review_row.update(
            {
                "review_reason": review_only_reason or classification_gate_reason or "stage3_review_only",
                "final_classification": classification,
                "classification_gate_reason": classification_gate_reason,
                "non_lexical_corroboration_count": corroboration,
                "tvc_match_surface": ocr_tvc.get("tvc_match_surface", "none"),
                "tvc_matched_alias": ocr_tvc.get("tvc_matched_alias", ""),
                "tvc_spoof_strong": ocr_tvc.get("tvc_spoof_strong", False),
                "registrar": registrar,
                "hosting_isp": hosting_isp,
                "hosting_country": hosting_country,
                "dns_records": dns_records,
                "hosting_ip": ip,
                "name_servers": name_servers,
            }
        )
    return asdict(
        ClassificationRecord(
            output_record=output_record if flagged_output else None,
            review_row=review_row,
            stage2_debug_row={
                "url": domain_url,
                "source_workbook": source_workbook,
                "shortlisted_cse": row.get("Cooresponding CSE", ""),
                "shortlisted_domain": row.get("Legitimate Domains", ""),
                "fetch_status": fetch_status,
                "final_landing_url": row.get("final_landing_url", ""),
                "parking_provider": row.get("parking_provider", ""),
                "parking_reason": row.get("parking_reason", ""),
                "brand_model_top1": brand_model_top1,
                "brand_model_confidence": round(float(brand_model_confidence), 4),
                "domain_model_top1": domain_model_top1,
                "domain_model_confidence": round(float(domain_model_confidence), 4),
                "model_brand_agrees_with_shortlist": model_brand_agrees_with_shortlist,
                "model_domain_agrees_with_shortlist": model_domain_agrees_with_shortlist,
                "model_feature_status": model_feature_status,
                "model_input_error": model_input_error,
                "model_usable": model_usable,
                "decision_code": model_feature_status,
                "reason_code": model_input_error or classification_gate_reason,
                **pipeline_module._stage1_debug_compat_payload(row),
            },
            stage3_debug_row={
                "url": domain_url,
                "source_workbook": source_workbook,
                "shortlisted_cse": row.get("Cooresponding CSE", ""),
                "shortlisted_domain": row.get("Legitimate Domains", ""),
                "fetch_status": fetch_status,
                "final_landing_url": row.get("final_landing_url", ""),
                "parking_provider": row.get("parking_provider", ""),
                "parking_reason": row.get("parking_reason", ""),
                "placeholder_or_parking_reason": row.get("placeholder_or_parking_reason", row.get("parking_reason", "")),
                "classification": classification,
                "confidence_band": confidence_band,
                "evidence_tier": evidence_tier,
                "lexical_score": row.get("lexical_score", 0.0),
                "hash_score": row.get("hash_score", 0.0),
                "old_fuzzy_hit": row.get("old_fuzzy_hit", False),
                "hybrid_lexical_hit": row.get("hybrid_lexical_hit", False),
                "strict_lexical_hit": row.get("strict_lexical_hit", False),
                "lexical_score_pass": row.get("lexical_score_pass", False),
                "fallback_rank_only": row.get("fallback_rank_only", False),
                "typo_anchor": row.get("typo_anchor", False),
                "hash_anchor": row.get("hash_anchor", False),
                "generic_token_only_match": row.get("generic_token_only_match", False),
                "direct_brand_evidence_count": row.get("direct_brand_evidence_count", 0),
                "stage1_passthrough": row.get("stage1_passthrough", False),
                "tvc_brand_detected": ocr_tvc.get("tvc_brand_detected", False),
                "tvc_detected_brand": ocr_tvc.get("tvc_detected_brand", "none"),
                "tvc_brand_spoofed": ocr_tvc.get("tvc_brand_spoofed", False),
                "tvc_match_surface": ocr_tvc.get("tvc_match_surface", "none"),
                "tvc_matched_alias": ocr_tvc.get("tvc_matched_alias", ""),
                "tvc_spoof_strong": ocr_tvc.get("tvc_spoof_strong", False),
                "ocr_text_len": len(str(ocr_tvc.get("ocr_text", "") or "")),
                "registrar": registrar,
                "hosting_isp": hosting_isp,
                "hosting_country": hosting_country,
                "dns_records": dns_records,
                "brand_model_top1": brand_model_top1,
                "brand_model_confidence": round(float(brand_model_confidence), 4),
                "domain_model_top1": domain_model_top1,
                "domain_model_confidence": round(float(domain_model_confidence), 4),
                "model_brand_agrees_with_shortlist": model_brand_agrees_with_shortlist,
                "model_domain_agrees_with_shortlist": model_domain_agrees_with_shortlist,
                "model_feature_status": model_feature_status,
                "model_input_error": model_input_error,
                "model_usable": model_usable,
                "decision_code": classification_gate_reason or classification,
                "reason_code": review_only_reason or classification_gate_reason or classification,
                "classification_gate_reason": classification_gate_reason,
                "review_only_reason": review_only_reason,
                "survival_path": classification_gate_reason if (flagged_output or review_sink) else "",
                "drop_path": "" if (flagged_output or review_sink) else classification_gate_reason,
                "non_lexical_corroboration_count": corroboration,
                **pipeline_module._stage1_debug_compat_payload(row),
            },
            checkpoint_patch=_patch(stage_status=classification_gate_reason or classification, final_pipeline_status="completed" if flagged_output else "review_only" if review_sink else "classification_failed", final_decision=classification if (flagged_output or review_sink) else "UNCLASSIFIED", failure_reason=review_only_reason or classification_gate_reason, submission_record=output_record if flagged_output else None),
            stage_event=_event(classification_gate_reason or classification),
            classification=classification,
            flagged_output=flagged_output,
            review_sink=review_sink,
        )
    )


async def run_hash_only_pipeline_with_ray_impl(
    *,
    df_filtered: pd.DataFrame,
    high_confidence_threshold: float,
    medium_confidence_threshold: float,
    failed_fetch_suspected_min: float | None = None,
    failed_fetch_review_min: float | None = None,
    run_context: RunContext | None = None,
    checkpoint_store=None,
    resume: bool = False,
    force_reprocess: bool = False,
    progress_mode: str | None = None,
) -> pd.DataFrame:
    del checkpoint_store

    from . import pipeline as pipeline_module

    ensure_ray_initialized()
    primitives = _get_ray_primitives()
    runtime_config = resolve_ray_runtime_config()
    progress_mode = resolve_progress_mode(progress_mode, execution_backend="ray")
    progress_enabled = progress_bars_enabled(progress_mode)
    logger.info(
        "Ray classify startup | rows=%d | progress_mode=%s | local_mode=%s | low_memory=%s | server_mode=%s | prewarm=%s | classify_actors=%d | classify_inflight=%d | ocr_actors=%d | ocr_batch={size=%d,delay_ms=%d}",
        len(df_filtered),
        progress_mode,
        bool(runtime_config.get("local_mode")),
        bool(runtime_config.get("low_memory_mode")),
        bool(runtime_config.get("server_mode")),
        bool(runtime_config.get("prewarm_actors")),
        int(runtime_config["classify_actors"]),
        int(runtime_config.get("classify_inflight", max(1, int(runtime_config["classify_actors"])))),
        int(runtime_config["ocr_actors"]),
        int(runtime_config.get("ocr_batch_size", 1) or 1),
        int(runtime_config.get("ocr_batch_delay_ms", 1) or 1),
    )
    checkpoint_actor = primitives["CheckpointWriterActor"].remote(_ray_context_dict(run_context)) if run_context is not None else None
    metrics_actor = primitives["MetricsActor"].remote()
    final_output_path = get_run_artifact_path(run_context, "final_output_csv", FINAL_OUTPUT)
    filtered_output_path = get_run_artifact_path(
        run_context,
        "final_output_filtered_csv",
        FINAL_OUTPUT.replace(".csv", "_filtered.csv"),
    )
    review_queue_path = get_run_artifact_path(run_context, "hash_review_queue_csv", pipeline_module.HASH_REVIEW_QUEUE_PATH)
    stage2_debug_path = get_run_artifact_path(run_context, "stage2_model_debug_csv", pipeline_module.STAGE2_MODEL_DEBUG_PATH)
    stage3_debug_path = get_run_artifact_path(run_context, "stage3_classification_debug_csv", pipeline_module.STAGE3_CLASSIFICATION_DEBUG_PATH)
    whois_actor = primitives["WhoisCoordinatorActor"].options(num_cpus=0).remote(20)
    ocr_num_gpus = 0.0
    try:
        import torch  # type: ignore
        if torch.cuda.is_available():
            ocr_num_gpus = 1.0
    except Exception:
        pass
    ocr_actors = [
        primitives["OcrWorkerActor"].options(
            num_cpus=1,
            num_gpus=ocr_num_gpus if index == 0 else 0,
        ).remote(
            int(runtime_config.get("ocr_batch_size", 32) or 32),
            int(runtime_config.get("ocr_batch_delay_ms", 25) or 25),
        )
        for index in range(int(runtime_config["ocr_actors"]))
    ]
    classifier_actors = [primitives["HashOnlyClassifierActor"].options(num_cpus=1, max_concurrency=1).remote(failed_fetch_suspected_min, failed_fetch_review_min) for _ in range(int(runtime_config["classify_actors"]))]
    output_records: list[dict[str, Any]] = []
    flagged_record_count = 0
    review_rows: list[dict[str, Any]] = []
    pending: dict[Any, dict[str, Any]] = {}
    failed_classifications = 0
    ocr_progress_stats: dict[str, Any] = {}
    dynamic_control_enabled = bool(runtime_config.get("enable_dynamic_control", True))
    target_cpu_utilization = float(runtime_config.get("target_cpu_utilization", 0.82) or 0.82)
    cpu_headroom_cores = max(1, int(runtime_config.get("cpu_headroom_cores", 6) or 6))
    severe_available_cpu_floor = max(1.0, float(max(1, cpu_headroom_cores - 2)))
    healthy_available_cpu_floor = float(cpu_headroom_cores + 2)
    control_interval_seconds = 2.0
    classify_inflight_cap = max(
        1,
        min(
            int(runtime_config.get("classify_inflight", max(1, len(classifier_actors))) or max(1, len(classifier_actors))),
            max(1, len(classifier_actors) * 2),
        ),
    )
    classify_inflight_floor = min(
        classify_inflight_cap,
        8 if runtime_config.get("server_mode") and not runtime_config.get("low_memory_mode") else 1,
    )
    controller_state: dict[str, Any] = {
        "enabled": dynamic_control_enabled,
        "classify_live_inflight": min(max(1, len(classifier_actors)), classify_inflight_cap),
        "classify_inflight_floor": classify_inflight_floor,
        "classify_inflight_cap": classify_inflight_cap,
        "action": "init",
        "reason": "startup",
        "available_cpu": 0.0,
        "cpu_utilization": 0.0,
        "event_loop_lag_ms": 0.0,
        "checkpoint_pending_rows": 0,
        "healthy_streak": 0,
        "ocr_queue_depth": 0,
        "progress_completed": 0,
        "target_cpu_utilization": target_cpu_utilization,
        "cpu_headroom_cores": cpu_headroom_cores,
    }
    stop_metrics = asyncio.Event()
    metrics_task = asyncio.create_task(
        _log_metrics_periodically(
            metrics_actor,
            stop_metrics,
            "classify",
            float(runtime_config["metrics_interval_seconds"]),
            checkpoint_actor=checkpoint_actor,
            stage_name="classify",
            details_getter=lambda: {
                "controller": {
                    "enabled": bool(controller_state.get("enabled", False)),
                    "classify_live_inflight": int(controller_state.get("classify_live_inflight", 0) or 0),
                    "classify_inflight_floor": int(controller_state.get("classify_inflight_floor", 0) or 0),
                    "classify_inflight_cap": int(controller_state.get("classify_inflight_cap", 0) or 0),
                    "available_cpu": float(controller_state.get("available_cpu", 0.0) or 0.0),
                    "cpu_utilization": float(controller_state.get("cpu_utilization", 0.0) or 0.0),
                    "event_loop_lag_ms": float(controller_state.get("event_loop_lag_ms", 0.0) or 0.0),
                    "checkpoint_pending_rows": int(controller_state.get("checkpoint_pending_rows", 0) or 0),
                    "action": str(controller_state.get("action", "") or ""),
                    "reason": str(controller_state.get("reason", "") or ""),
                    "healthy_streak": int(controller_state.get("healthy_streak", 0) or 0),
                    "progress_completed": int(controller_state.get("progress_completed", 0) or 0),
                    "target_cpu_utilization": float(controller_state.get("target_cpu_utilization", 0.0) or 0.0),
                    "cpu_headroom_cores": int(controller_state.get("cpu_headroom_cores", 0) or 0),
                },
                "inflight": len(pending),
                "flagged": flagged_record_count,
                "review": len(review_rows),
                "failed": failed_classifications,
                "ocr": dict(ocr_progress_stats or {}),
                "classify_actors": len(classifier_actors),
            },
            resource_snapshot_getter=debug_ray_resource_snapshot,
            emit_logs=not progress_enabled,
        )
    )
    if bool(runtime_config.get("prewarm_actors")):
        warm_refs = [actor.warm.remote() for actor in classifier_actors]
        warm_refs.extend(actor.warm.remote() for actor in ocr_actors)
        if warm_refs:
            logger.info(
                "Ray classify prewarming actors | classifier=%d | ocr=%d",
                len(classifier_actors),
                len(ocr_actors),
            )
            await _ray_get(warm_refs)
            logger.info("Ray classify actor prewarm complete")

    df_filtered = df_filtered.copy()
    df_filtered = pipeline_module._normalize_replayed_columns(df_filtered, ["final_landing_url"])
    existing_review_df = pipeline_module._read_existing_review_queue(review_queue_path)
    if "hash_score" not in df_filtered.columns:
        df_filtered["hash_score"] = 0.0
    df_filtered["hash_score"] = pd.to_numeric(df_filtered["hash_score"], errors="coerce").fillna(0.0)
    confidence_series = df_filtered["confidence_band"] if "confidence_band" in df_filtered.columns else pd.Series([""] * len(df_filtered), index=df_filtered.index)
    df_filtered["confidence_band"] = [pipeline_module._normalize_confidence_band(raw_band, score, high_confidence_threshold, medium_confidence_threshold) for raw_band, score in zip(confidence_series, df_filtered["hash_score"])]
    df_filtered["evidence_tier"] = [pipeline_module._normalize_evidence_tier(row) for row in df_filtered.to_dict("records")]
    df_filtered["review_reason"] = [
        "fetch_failed_lexical_hit" if str(row.get("fetch_status", "")).strip().lower() in {"failed", "timeout"} and pipeline_module._as_bool_flag(row.get("strict_lexical_hit"))
        else "low_confidence_hash_bypass" if pipeline_module._as_bool_flag(row.get("hash_anchor"))
        else "low_confidence_strict_lexical" if pipeline_module._as_bool_flag(row.get("strict_lexical_hit"))
        else "low_confidence_lexical_score_pass" if pipeline_module._as_bool_flag(row.get("lexical_score_pass"))
        else "low_confidence_admitted"
        for row in df_filtered.to_dict("records")
    ]

    classified_df = df_filtered.copy()
    completed_record_keys = set()
    if checkpoint_actor is not None and resume and not force_reprocess:
        completed_record_keys = await _ray_get(checkpoint_actor.get_completed_record_keys.remote())
    if checkpoint_actor is not None and run_context is not None:
        pending_rows = []
        ensure_records = []
        for row in classified_df.to_dict("records"):
            domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
            normalized_url = domain_url.strip().lower()
            source_workbook = str(row.get("source_workbook", "") or "")
            ensure_records.append({"raw_url": domain_url, "normalized_url": normalized_url, "source_workbook": source_workbook})
            if make_record_key(normalized_url, source_workbook) in completed_record_keys:
                continue
            pending_rows.append(row)
        checkpoint_actor.ensure_url_results.remote(ensure_records)
        classified_df = pd.DataFrame(pending_rows)
    if classified_df.empty:
        existing_records = await _ray_get(checkpoint_actor.get_terminal_submission_records.remote()) if checkpoint_actor is not None else []
        logger.warning(
            "Classify stage: all %d input rows already marked completed in checkpoint. "
            "Reusing %d existing submission records from previous run. "
            "Use --force-reprocess to re-classify all rows from scratch.",
            len(df_filtered),
            len(existing_records or []),
        )
        empty_df = pd.DataFrame(existing_records, columns=pipeline_module._submission_record_columns()) if existing_records else pd.DataFrame(columns=pipeline_module._submission_record_columns())
        empty_df.to_csv(final_output_path, index=False, encoding="utf-8")
        empty_df.to_csv(filtered_output_path, index=False, encoding="utf-8")
        sync_run_artifact(run_context, "final_output_csv", src_path=final_output_path, best_effort=True)
        sync_run_artifact(run_context, "final_output_filtered_csv", src_path=filtered_output_path, best_effort=True)
        pipeline_module._write_debug_csv([], stage2_debug_path, run_context=run_context, artifact_key="stage2_model_debug_csv")
        pipeline_module._write_debug_csv([], stage3_debug_path, run_context=run_context, artifact_key="stage3_classification_debug_csv")
        pipeline_module._write_hash_review_queue(
            pipeline_module._merge_review_queue_frames(existing_review_df),
            run_context=run_context,
            output_path=review_queue_path,
        )
        return empty_df

    stage2_rows: list[dict[str, Any]] = []
    stage3_rows: list[dict[str, Any]] = []
    rows_to_process = classified_df.to_dict("records")
    classify_progress = ProgressTracker(total=len(rows_to_process))
    progress_stop = asyncio.Event()
    classify_started_monotonic = time.perf_counter()
    last_debug_flush_monotonic = classify_started_monotonic
    last_debug_flush_completed = 0
    controller_state["classify_live_inflight"] = min(
        classify_inflight_cap,
        max(classify_inflight_floor, int(controller_state.get("classify_live_inflight", classify_inflight_floor) or classify_inflight_floor)),
    )
    next_row_index = 0

    async def _replace_classifier_actor(actor_slot: int, *, reason: str) -> None:
        if actor_slot < 0 or actor_slot >= len(classifier_actors):
            return
        old_actor = classifier_actors[actor_slot]
        try:
            await _ray_get(old_actor.close.remote(), _label=f"classifier_close:{actor_slot}")
        except Exception:
            pass
        try:
            primitives["ray"].kill(old_actor, no_restart=True)
        except Exception:
            pass
        classifier_actors[actor_slot] = primitives["HashOnlyClassifierActor"].options(
            num_cpus=1,
            max_concurrency=1,
        ).remote(failed_fetch_suspected_min, failed_fetch_review_min)
        logger.warning("Ray classify actor replaced | slot=%d | reason=%s", actor_slot, reason)

    def _submit_classify_row(*, row: dict[str, Any], sequence_number: int, actor_slot: int, attempt_count: int) -> None:
        classifier = classifier_actors[actor_slot]
        ocr_actor = ocr_actors[(max(1, sequence_number) - 1) % len(ocr_actors)]
        domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
        normalized_url = domain_url.strip().lower()
        source_workbook = str(row.get("source_workbook", "") or "")
        record_key = make_record_key(normalized_url, source_workbook)
        worker_id = f"classify-{actor_slot}"
        pending[classifier.classify_row.remote(row, sequence_number, ocr_actor, whois_actor)] = {
            "row": row,
            "worker_id": worker_id,
            "record_key": record_key,
            "submitted_monotonic": time.perf_counter(),
            "actor_slot": actor_slot,
            "attempt_count": int(attempt_count),
            "sequence_number": int(sequence_number),
        }

    def _submit_until_cap() -> None:
        nonlocal next_row_index
        live_cap = int(controller_state.get("classify_live_inflight", classify_inflight_cap) or classify_inflight_cap)
        while next_row_index < len(rows_to_process) and len(pending) < live_cap:
            row = rows_to_process[next_row_index]
            sequence_number = next_row_index + 1
            actor_slot = next_row_index % len(classifier_actors)
            _submit_classify_row(
                row=row,
                sequence_number=sequence_number,
                actor_slot=actor_slot,
                attempt_count=0,
            )
            next_row_index += 1

    def _refresh_progress_bar(progress_bar: Any | None) -> None:
        if progress_bar is None:
            return
        completed = classify_progress.completed
        if completed > progress_bar.n:
            progress_bar.update(completed - progress_bar.n)
        progress_bar.set_postfix(
            _build_classify_progress_postfix(
                progress_tracker=classify_progress,
                started_monotonic=classify_started_monotonic,
                inflight=len(pending),
                flagged=flagged_record_count,
                review=len(review_rows),
                failed=failed_classifications,
                ocr_stats=ocr_progress_stats,
                classify_actor_count=len(classifier_actors),
            ),
            refresh=False,
        )
        progress_bar.refresh()

    def _flush_debug_artifacts(*, force: bool = False) -> None:
        nonlocal last_debug_flush_monotonic, last_debug_flush_completed
        completed = classify_progress.completed
        now = time.perf_counter()
        if not force:
            enough_rows = (completed - last_debug_flush_completed) >= 1000
            enough_time = (now - last_debug_flush_monotonic) >= 15.0
            if not ((stage2_rows or stage3_rows) and (enough_rows or enough_time)):
                return
        _append_debug_rows_csv(
            rows=stage2_rows,
            output_path=stage2_debug_path,
            run_context=run_context,
            artifact_key="stage2_model_debug_csv",
        )
        _append_debug_rows_csv(
            rows=stage3_rows,
            output_path=stage3_debug_path,
            run_context=run_context,
            artifact_key="stage3_classification_debug_csv",
        )
        stage2_rows.clear()
        stage3_rows.clear()
        last_debug_flush_monotonic = now
        last_debug_flush_completed = completed

    async def _progress_monitor(progress_bar: Any | None, started_monotonic: float) -> None:
        nonlocal ocr_progress_stats
        if progress_bar is None:
            return
        while not progress_stop.is_set():
            if ocr_actors:
                try:
                    stats_rows = await _ray_get([actor.stats.remote() for actor in ocr_actors])
                    ocr_progress_stats = _aggregate_ocr_stats([dict(item or {}) for item in list(stats_rows or [])])
                except Exception:
                    ocr_progress_stats = {}
            progress_bar.set_postfix(
                _build_classify_progress_postfix(
                    progress_tracker=classify_progress,
                    started_monotonic=started_monotonic,
                    inflight=len(pending),
                    flagged=flagged_record_count,
                    review=len(review_rows),
                    failed=failed_classifications,
                    ocr_stats=ocr_progress_stats,
                    classify_actor_count=len(classifier_actors),
                ),
                refresh=False,
            )
            if classify_progress.completed > progress_bar.n:
                progress_bar.update(classify_progress.completed - progress_bar.n)
            progress_bar.refresh()
            try:
                await asyncio.wait_for(progress_stop.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass

    heartbeat_stop = asyncio.Event()
    heartbeat_workers: set[str] = set()
    controller_stop = asyncio.Event()

    async def _heartbeat_monitor() -> None:
        nonlocal heartbeat_workers
        if checkpoint_actor is None or run_context is None:
            return
        while not heartbeat_stop.is_set():
            now = time.perf_counter()
            active_workers: set[str] = set()
            for context in list(pending.values()):
                worker_id = str(context.get("worker_id", "") or "")
                record_key = str(context.get("record_key", "") or "")
                row = dict(context.get("row") or {})
                normalized_url = str(row.get("Identified Phishing/Suspected Domain Name", "") or "").strip().lower()
                if not worker_id:
                    continue
                active_workers.add(worker_id)
                checkpoint_actor.update_worker_heartbeat.remote(
                    stage_name="classify",
                    worker_id=worker_id,
                    record_key=record_key,
                    state="running",
                    task_kind="classify_row",
                    item_age_s=max(0.0, now - float(context.get("submitted_monotonic", now) or now)),
                    details={"url": normalized_url, "inflight": len(pending)},
                )
            for worker_id in sorted(heartbeat_workers - active_workers):
                checkpoint_actor.clear_worker_heartbeat.remote(stage_name="classify", worker_id=worker_id)
            heartbeat_workers = active_workers
            try:
                await asyncio.wait_for(heartbeat_stop.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                pass

    async def _reap_stale_classify_tasks() -> None:
        nonlocal failed_classifications
        now = time.perf_counter()
        stale_contexts: list[tuple[Any, dict[str, Any], float]] = []
        for ref, context in list(pending.items()):
            submitted = float(context.get("submitted_monotonic", now) or now)
            age_seconds = max(0.0, now - submitted)
            if age_seconds < 180.0:
                continue
            stale_contexts.append((ref, dict(context), age_seconds))
        for ref, context, _age_seconds in stale_contexts:
            current_context = pending.pop(ref, None)
            if current_context is None:
                continue
            worker_id = str(current_context.get("worker_id", "") or "")
            if checkpoint_actor is not None and worker_id:
                checkpoint_actor.clear_worker_heartbeat.remote(stage_name="classify", worker_id=worker_id)
            row = dict(current_context.get("row") or {})
            domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
            normalized_url = domain_url.strip().lower()
            source_workbook = str(row.get("source_workbook", "") or "")
            actor_slot = int(current_context.get("actor_slot", -1) or -1)
            attempt_count = int(current_context.get("attempt_count", 0) or 0)
            sequence_number = int(current_context.get("sequence_number", 0) or 0) or 1
            if attempt_count >= 1:
                failed_classifications += 1
                classify_progress.mark_completed(final_status="classification_failed")
                metrics_actor.increment.remote("classify.failed", 1.0)
                if checkpoint_actor is not None and run_context is not None:
                    checkpoint_actor.upsert_url_result.remote(
                        stage_result_patch(
                            run_id=run_context.run_id,
                            raw_url=domain_url,
                            normalized_url=normalized_url,
                            source_workbook=source_workbook,
                            stage_name="classify",
                            stage_status="failed",
                            current_stage="classify",
                            worker_id="ray-classify",
                            error_type="RuntimeError",
                            error_message="stale_classify_task_after_retry",
                            final_pipeline_status="classification_failed",
                            final_decision="UNCLASSIFIED",
                            failure_reason="stale_classify_task_after_retry",
                        )
                    )
                continue
            if actor_slot >= 0:
                await _replace_classifier_actor(actor_slot, reason="stale_classify_task")
            retry_slot = actor_slot if 0 <= actor_slot < len(classifier_actors) else 0
            _submit_classify_row(
                row=row,
                sequence_number=sequence_number,
                actor_slot=retry_slot,
                attempt_count=attempt_count + 1,
            )

    logging_redirect_ctx = tqdm_logging_redirect(progress_enabled)
    progress_bar_ctx = managed_progress_bar(
        enabled=progress_enabled,
        desc="Ray classify",
        total=len(rows_to_process),
        unit="row",
        position=0,
    )
    logging_redirect_ctx.__enter__()
    progress_bar = progress_bar_ctx.__enter__()
    progress_task = asyncio.create_task(_progress_monitor(progress_bar, classify_started_monotonic)) if progress_bar is not None else None
    heartbeat_task = asyncio.create_task(_heartbeat_monitor()) if checkpoint_actor is not None and run_context is not None else None

    async def _control_monitor() -> None:
        if not dynamic_control_enabled and checkpoint_actor is None:
            return
        last_tick = time.perf_counter()
        last_checkpoint_flush = last_tick
        last_completed = classify_progress.completed
        while not controller_stop.is_set():
            try:
                await asyncio.wait_for(controller_stop.wait(), timeout=control_interval_seconds)
                break
            except asyncio.TimeoutError:
                pass
            now = time.perf_counter()
            expected_tick = last_tick + control_interval_seconds
            event_loop_lag_ms = max(0.0, (now - expected_tick) * 1000.0)
            last_tick = now
            resource_snapshot = debug_ray_resource_snapshot()
            available_cpu = float(resource_snapshot.get("available_cpu", 0.0) or 0.0)
            cluster_cpu = float(resource_snapshot.get("cluster_cpu", 0.0) or 0.0)
            used_cpu = float(resource_snapshot.get("used_cpu", 0.0) or 0.0)
            cpu_utilization = max(0.0, min(1.0, used_cpu / cluster_cpu)) if cluster_cpu > 0 else 0.0
            checkpoint_backlog: dict[str, Any] = {}
            if checkpoint_actor is not None:
                try:
                    checkpoint_backlog = dict(await _ray_get(checkpoint_actor.get_backlog_snapshot.remote()) or {})
                except Exception:
                    logger.exception("Failed to snapshot checkpoint backlog for classify controller")
                if (now - last_checkpoint_flush) >= 10.0:
                    checkpoint_actor.export_all.remote()
                    last_checkpoint_flush = now
            checkpoint_pending_rows = int(checkpoint_backlog.get("pending_rows_total", 0) or 0)
            ocr_queue_depth = int(ocr_progress_stats.get("queue_depth", 0) or 0)
            completed_now = classify_progress.completed
            completed_delta = max(0, completed_now - last_completed)
            last_completed = completed_now
            severe_reasons: list[str] = []
            if available_cpu < severe_available_cpu_floor:
                severe_reasons.append("cpu_headroom_low")
            if available_cpu < float(cpu_headroom_cores) and cpu_utilization > min(0.99, target_cpu_utilization + 0.12):
                severe_reasons.append("cpu_utilization")
            server_mode = bool(runtime_config.get("server_mode"))
            if event_loop_lag_ms > (3000.0 if server_mode else 250.0):
                severe_reasons.append("event_loop_lag")
            if checkpoint_pending_rows > 20000:
                severe_reasons.append("checkpoint_backlog")
            if ocr_queue_depth > max(32, len(pending) * 2):
                severe_reasons.append("ocr_backlog")
            if dynamic_control_enabled and severe_reasons:
                controller_state["healthy_streak"] = 0
                if int(controller_state["classify_live_inflight"]) > classify_inflight_floor:
                    controller_state["classify_live_inflight"] = max(
                        classify_inflight_floor,
                        int(controller_state["classify_live_inflight"]) - 4,
                    )
                    controller_state["action"] = "downshift"
                else:
                    controller_state["action"] = "hold"
                controller_state["reason"] = ",".join(severe_reasons[:3])
            else:
                healthy_window = (
                    available_cpu > healthy_available_cpu_floor
                    and cpu_utilization < min(0.99, target_cpu_utilization + 0.05)
                    and event_loop_lag_ms < 100.0
                    and checkpoint_pending_rows < 5000
                    and ocr_queue_depth < max(8, len(ocr_actors) * 8)
                    and (completed_delta > 0 or not pending)
                )
                if dynamic_control_enabled and healthy_window:
                    controller_state["healthy_streak"] = int(controller_state.get("healthy_streak", 0) or 0) + 1
                    if int(controller_state["healthy_streak"]) >= 1:
                        controller_state["healthy_streak"] = 0
                        if int(controller_state["classify_live_inflight"]) < classify_inflight_cap:
                            controller_state["classify_live_inflight"] = min(
                                classify_inflight_cap,
                                int(controller_state["classify_live_inflight"]) + 12,
                            )
                            controller_state["action"] = "upshift"
                            controller_state["reason"] = "healthy_window"
                        else:
                            controller_state["action"] = "hold"
                            controller_state["reason"] = "at_cap"
                    else:
                        controller_state["action"] = "hold"
                        controller_state["reason"] = "healthy_window_pending"
                else:
                    controller_state["healthy_streak"] = 0
                    controller_state["action"] = "hold"
                    controller_state["reason"] = "dynamic_control_disabled" if not dynamic_control_enabled else "steady"
            controller_state.update(
                {
                    "available_cpu": round(available_cpu, 3),
                    "cpu_utilization": round(cpu_utilization, 3),
                    "event_loop_lag_ms": round(event_loop_lag_ms, 3),
                    "checkpoint_pending_rows": checkpoint_pending_rows,
                    "ocr_queue_depth": ocr_queue_depth,
                    "progress_completed": int(completed_now),
                }
            )

    control_task = asyncio.create_task(_control_monitor()) if (checkpoint_actor is not None or dynamic_control_enabled) else None

    _submit_until_cap()
    _refresh_progress_bar(progress_bar)
    try:
        while pending:
            await _reap_stale_classify_tasks()
            if not pending:
                break
            ready, _ = await _ray_wait(list(pending.keys()), num_returns=min(16, len(pending)), timeout=1.0)
            if not ready:
                _refresh_progress_bar(progress_bar)
                continue
            for ref in ready:
                context = pending.pop(ref)
                worker_id = str(context.get("worker_id", "") or "")
                if checkpoint_actor is not None and worker_id:
                    checkpoint_actor.clear_worker_heartbeat.remote(stage_name="classify", worker_id=worker_id)
                row = dict(context["row"])
                domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
                normalized_url = domain_url.strip().lower()
                source_workbook = str(row.get("source_workbook", "") or "")
                try:
                    result = dict(await _ray_get(ref) or {})
                except Exception as exc:
                    error_type = type(exc).__name__
                    error_message = str(exc)
                    failed_classifications += 1
                    classify_progress.mark_completed(final_status="classification_failed")
                    metrics_actor.increment.remote("classify.failed", 1.0)
                    if checkpoint_actor is not None and run_context is not None:
                        checkpoint_actor.upsert_url_result.remote(stage_result_patch(run_id=run_context.run_id, raw_url=domain_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="classify", stage_status="failed", current_stage="classify", worker_id="ray-classify", error_type=error_type, error_message=error_message, final_pipeline_status="classification_failed", final_decision="UNCLASSIFIED", failure_reason=error_message))
                    continue
                if result.get("output_record") is not None and checkpoint_actor is None:
                    output_records.append(dict(result["output_record"]))
                if result.get("review_row") is not None:
                    review_rows.append(dict(result["review_row"]))
                stage2_rows.append(dict(result.get("stage2_debug_row") or {}))
                stage3_rows.append(dict(result.get("stage3_debug_row") or {}))
                patch = dict(result.get("checkpoint_patch") or {})
                event = dict(result.get("stage_event") or {})
                if patch and run_context is not None:
                    patch["run_id"] = run_context.run_id
                    patch["record_key"] = make_record_key(normalized_url, source_workbook)
                if event and run_context is not None:
                    event["run_id"] = run_context.run_id
                    event["record_key"] = make_record_key(normalized_url, source_workbook)
                if checkpoint_actor is not None:
                    if patch:
                        checkpoint_actor.upsert_url_result.remote(patch)
                    if event:
                        checkpoint_actor.append_stage_event.remote(event)
                metrics_actor.increment.remote("classify.completed", 1.0)
                classify_progress.mark_completed(
                    final_status="review_only" if bool(result.get("review_sink")) else "completed"
                )
                if result.get("output_record") is not None:
                    flagged_record_count += 1
            _flush_debug_artifacts()
            _submit_until_cap()
            _refresh_progress_bar(progress_bar)
        merged_review_df = pipeline_module._merge_review_queue_frames(existing_review_df, pd.DataFrame(review_rows))
        pipeline_module._write_hash_review_queue(
            merged_review_df,
            run_context=run_context,
            output_path=review_queue_path,
        )
        if checkpoint_actor is not None:
            await _ray_get(checkpoint_actor.export_all.remote())
            output_records = list(await _ray_get(checkpoint_actor.get_terminal_submission_records.remote()) or [])
        df_out = pd.DataFrame(output_records, columns=pipeline_module._submission_record_columns())
        df_out.to_csv(final_output_path, index=False, encoding="utf-8")
        flagged_df = df_out[df_out["Phishing/Suspected Domains (i.e. Class Label)"].isin(["Phishing", "Suspected"])].copy()
        flagged_df.to_csv(filtered_output_path, index=False, encoding="utf-8")
        sync_run_artifact(run_context, "final_output_csv", src_path=final_output_path, best_effort=True)
        sync_run_artifact(run_context, "final_output_filtered_csv", src_path=filtered_output_path, best_effort=True)
        _flush_debug_artifacts(force=True)
        _refresh_progress_bar(progress_bar)
        return df_out
    finally:
        progress_stop.set()
        if progress_task is not None:
            await asyncio.gather(progress_task, return_exceptions=True)
        controller_stop.set()
        if control_task is not None:
            await asyncio.gather(control_task, return_exceptions=True)
        heartbeat_stop.set()
        if heartbeat_task is not None:
            await asyncio.gather(heartbeat_task, return_exceptions=True)
        if checkpoint_actor is not None:
            for worker_id in sorted(heartbeat_workers):
                checkpoint_actor.clear_worker_heartbeat.remote(stage_name="classify", worker_id=worker_id)
        _refresh_progress_bar(progress_bar)
        progress_bar_ctx.__exit__(None, None, None)
        logging_redirect_ctx.__exit__(None, None, None)
        stop_metrics.set()
        await asyncio.gather(metrics_task, return_exceptions=True)
        close_refs = [actor.close.remote() for actor in classifier_actors]
        close_refs.extend(actor.close.remote() for actor in ocr_actors)
        if close_refs:
            await _ray_get(close_refs)
        if checkpoint_actor is not None:
            try:
                await _ray_get(checkpoint_actor.export_all.remote())
            except Exception:
                logger.exception("Failed to export classify checkpoint state before shutdown")
            await _ray_get(checkpoint_actor.close.remote())
