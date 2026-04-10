from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import datetime
import logging
import socket
import time
from typing import Any
from urllib.parse import urlparse

import pandas as pd

from .config import APPLICATION_ID, ASN_DB_PATH, CITY_DB_PATH, FINAL_OUTPUT, resolve_ray_runtime_config
from .geoip_utils import enrich_with_geoip
from .reliability import RunContext, make_record_key, stage_result_patch, utc_now_iso
from .ray_runtime import (
    ClassificationRecord,
    _get_ray_primitives,
    _log_metrics_periodically,
    _ray_context_dict,
    _ray_get,
    _ray_wait,
    ensure_ray_initialized,
)

logger = logging.getLogger(__name__)


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

    if fetch_status not in eligible_fetch_statuses:
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
                remarks="weak_or_single_signal_match; NA values are due to privacy issues.",
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
    try:
        net_feats = await extract_network_features_async(domain_url)
    except Exception:
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

    resolved_ip = str(net_feats.get("ip_address") or "") or None
    try:
        loop = asyncio.get_running_loop()
        resolved_ip = await asyncio.wait_for(loop.run_in_executor(None, socket.gethostbyname, host), timeout=3.0)
    except Exception:
        pass

    def _get_rdap_url(domain_host: str) -> str:
        ext = tldextract.extract(domain_host)
        tld = ext.suffix.split(".")[-1] if ext.suffix else ""
        return pipeline_module.RDAP_DIRECT_URLS.get(tld, pipeline_module.RDAP_FALLBACK_URL)

    reg_data = None
    registration_lookup_status = "unknown"
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
            remarks="weak_or_single_signal_match; NA values are due to privacy issues.",
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

    if reg_data is None and resolved_ip is not None:
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
        except Exception:
            pass

    dns_records = "NA"
    if resolved_ip is not None:
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
            pass

    rd = reg_data or {}
    reg_date = rd.get("reg_date", "NA")
    registrar = rd.get("registrar", "NA")
    registrant_name = rd.get("registrant_name", "NA")
    registrant_country = rd.get("registrant_country", "NA")
    name_servers = rd.get("name_servers", "NA")
    geo_input = pd.DataFrame([{"url": domain_url, "ip_address": resolved_ip or "NA"}])
    geo_dict = enrich_with_geoip(geo_input, ASN_DB_PATH, CITY_DB_PATH).iloc[0].to_dict()
    ip = str(geo_dict.get("ip_address") or (resolved_ip or "NA"))
    hosting_isp = str(geo_dict.get("asn_org", "NA")) if geo_dict.get("asn_org") and not pd.isna(geo_dict.get("asn_org")) else "NA"
    hosting_country = str(geo_dict.get("country", "NA")) if geo_dict.get("country") and not pd.isna(geo_dict.get("country")) else "NA"
    if feature_cols and scaler is not None and imputer is not None:
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
        remarks=(
            "non_aligned_or_weak_cse_similarity; NA values are due to privacy issues."
            if classification == "Legitimate"
            else "weak_or_single_signal_match; NA values are due to privacy issues."
            if evidence_tier == "weak_evidence"
            else "NA values are due to privacy issues."
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
) -> pd.DataFrame:
    del checkpoint_store

    from . import pipeline as pipeline_module

    ensure_ray_initialized()
    primitives = _get_ray_primitives()
    runtime_config = resolve_ray_runtime_config()
    logger.info(
        "Ray classify startup | rows=%d | local_mode=%s | low_memory=%s | server_mode=%s | prewarm=%s | classify_actors=%d | classify_inflight=%d | ocr_actors=%d | ocr_batch={size=%d,delay_ms=%d}",
        len(df_filtered),
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
    stop_metrics = asyncio.Event()
    metrics_task = asyncio.create_task(_log_metrics_periodically(metrics_actor, stop_metrics, "classify", float(runtime_config["metrics_interval_seconds"])))
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
    filtered_output_path = FINAL_OUTPUT.replace(".csv", "_filtered.csv")
    existing_review_df = pipeline_module._read_existing_review_queue(pipeline_module.HASH_REVIEW_QUEUE_PATH)
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
        empty_df = pd.DataFrame(existing_records, columns=pipeline_module._submission_record_columns()) if existing_records else pd.DataFrame(columns=pipeline_module._submission_record_columns())
        empty_df.to_csv(FINAL_OUTPUT, index=False, encoding="utf-8")
        empty_df.to_csv(filtered_output_path, index=False, encoding="utf-8")
        pipeline_module._write_debug_csv([], pipeline_module.STAGE2_MODEL_DEBUG_PATH)
        pipeline_module._write_debug_csv([], pipeline_module.STAGE3_CLASSIFICATION_DEBUG_PATH)
        pipeline_module._write_hash_review_queue(pipeline_module._merge_review_queue_frames(existing_review_df))
        return empty_df

    output_records: list[dict[str, Any]] = []
    review_rows: list[dict[str, Any]] = []
    stage2_rows: list[dict[str, Any]] = []
    stage3_rows: list[dict[str, Any]] = []
    pending: dict[Any, dict[str, Any]] = {}
    rows_to_process = classified_df.to_dict("records")
    classify_inflight = int(runtime_config.get("classify_inflight", max(1, len(classifier_actors))))
    next_row_index = 0

    def _submit_until_cap() -> None:
        nonlocal next_row_index
        while next_row_index < len(rows_to_process) and len(pending) < classify_inflight:
            row = rows_to_process[next_row_index]
            sequence_number = next_row_index + 1
            classifier = classifier_actors[next_row_index % len(classifier_actors)]
            ocr_actor = ocr_actors[next_row_index % len(ocr_actors)]
            pending[classifier.classify_row.remote(row, sequence_number, ocr_actor, whois_actor)] = {"row": row}
            next_row_index += 1

    _submit_until_cap()
    try:
        while pending:
            ready, _ = await _ray_wait(list(pending.keys()), num_returns=min(16, len(pending)), timeout=1.0)
            if not ready:
                continue
            for ref in ready:
                context = pending.pop(ref)
                row = dict(context["row"])
                domain_url = str(row.get("Identified Phishing/Suspected Domain Name", "")).strip()
                normalized_url = domain_url.strip().lower()
                source_workbook = str(row.get("source_workbook", "") or "")
                try:
                    result = dict(await _ray_get(ref) or {})
                except Exception as exc:
                    error_type = type(exc).__name__
                    error_message = str(exc)
                    if checkpoint_actor is not None and run_context is not None:
                        checkpoint_actor.upsert_url_result.remote(stage_result_patch(run_id=run_context.run_id, raw_url=domain_url, normalized_url=normalized_url, source_workbook=source_workbook, stage_name="classify", stage_status="failed", current_stage="classify", worker_id="ray-classify", error_type=error_type, error_message=error_message, final_pipeline_status="classification_failed", final_decision="UNCLASSIFIED", failure_reason=error_message))
                    continue
                if result.get("output_record") is not None:
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
            _submit_until_cap()
        merged_review_df = pipeline_module._merge_review_queue_frames(existing_review_df, pd.DataFrame(review_rows))
        pipeline_module._write_hash_review_queue(merged_review_df)
        df_out = pd.DataFrame(output_records, columns=pipeline_module._submission_record_columns())
        df_out.to_csv(FINAL_OUTPUT, index=False, encoding="utf-8")
        flagged_df = df_out[df_out["Phishing/Suspected Domains (i.e. Class Label)"].isin(["Phishing", "Suspected"])].copy()
        flagged_df.to_csv(filtered_output_path, index=False, encoding="utf-8")
        pipeline_module._write_debug_csv(stage2_rows, pipeline_module.STAGE2_MODEL_DEBUG_PATH)
        pipeline_module._write_debug_csv(stage3_rows, pipeline_module.STAGE3_CLASSIFICATION_DEBUG_PATH)
        if checkpoint_actor is not None:
            checkpoint_actor.export_all.remote()
        return df_out
    finally:
        stop_metrics.set()
        await asyncio.gather(metrics_task, return_exceptions=True)
        close_refs = [actor.close.remote() for actor in classifier_actors]
        close_refs.extend(actor.close.remote() for actor in ocr_actors)
        if close_refs:
            await _ray_get(close_refs)
        if checkpoint_actor is not None:
            await _ray_get(checkpoint_actor.close.remote())
