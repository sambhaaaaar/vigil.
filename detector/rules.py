"""
Stage 1 — Rule-Based Anomaly Detector

Three detection rules for Razorpay payment infrastructure:
  1. CREDENTIAL_STUFFING — high failed-login rate per IP
  2. ADMIN_ANOMALY — admin hitting unusual endpoints at unusual hours
  3. MERCHANT_REFUND_SPIKE — refund volume far exceeds actor's baseline
"""

import json
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from typing import Any


# ─── Configuration ──────────────────────────────────────────────────────
CREDENTIAL_STUFFING_THRESHOLD = 10       # failed logins per IP in window
CREDENTIAL_STUFFING_WINDOW_MIN = 10      # sliding window in minutes

ADMIN_UNUSUAL_HOURS = range(0, 7)        # 00:00 — 06:59 UTC
ADMIN_KNOWN_ENDPOINTS = {
    # Endpoints that are "normal" for admins — anything else is flagged
    "/admin/dashboard",
    "/admin/merchants",
    "/admin/reports",
    "/admin/support-tickets",
}

MERCHANT_DRIFT_MULTIPLIER = 5            # flag if rate >= 5x baseline
MERCHANT_DRIFT_WINDOW_MIN = 30           # recent window to measure spike
MERCHANT_DRIFT_BASELINE_HRS = 24         # baseline window


def parse_ts(ts_str: str) -> datetime:
    """Parse ISO timestamp string to datetime."""
    return datetime.fromisoformat(ts_str)


class Flag:
    """Represents a single anomaly flag raised by a detection rule."""

    _counter = 0

    def __init__(self, rule: str, severity_hint: str, events: list[str],
                 evidence: dict, timestamp: str):
        Flag._counter += 1
        self.flag_id = f"FLG-{str(Flag._counter).zfill(3)}"
        self.rule = rule
        self.severity_hint = severity_hint
        self.events = events
        self.evidence = evidence
        self.timestamp = timestamp

    def to_dict(self) -> dict:
        return {
            "flag_id": self.flag_id,
            "rule": self.rule,
            "severity_hint": self.severity_hint,
            "events": self.events,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }


def detect_credential_stuffing(events: list[dict]) -> list[Flag]:
    """
    Rule 1: Credential Stuffing Detection
    
    Logic: Count failed login_attempt events per IP in a sliding window.
    Flag if any IP has >= threshold failures in the window, especially
    if attempts span many distinct actor_ids (distributed attack).
    """
    flags = []
    
    # Filter to login attempts
    login_events = [e for e in events if e["action"] == "login_attempt"]
    if not login_events:
        return flags

    # Group by IP
    ip_events: dict[str, list[dict]] = defaultdict(list)
    for evt in login_events:
        ip_events[evt["ip"]].append(evt)

    for ip, ip_evts in ip_events.items():
        failed = [e for e in ip_evts if e["status"] == "failed"]
        if len(failed) < CREDENTIAL_STUFFING_THRESHOLD:
            continue

        # Sort by timestamp
        failed.sort(key=lambda e: e["timestamp"])

        # Sliding window check
        window = timedelta(minutes=CREDENTIAL_STUFFING_WINDOW_MIN)
        i = 0
        for j in range(len(failed)):
            while parse_ts(failed[j]["timestamp"]) - parse_ts(failed[i]["timestamp"]) > window:
                i += 1
            window_count = j - i + 1
            if window_count >= CREDENTIAL_STUFFING_THRESHOLD:
                # Found a cluster — collect all events in this window
                window_events = failed[i:j + 1]
                # Also include any successes from same IP in window
                all_ip_in_window = [
                    e for e in ip_evts
                    if parse_ts(failed[i]["timestamp"]) <= parse_ts(e["timestamp"])
                    <= parse_ts(failed[j]["timestamp"])
                ]
                unique_actors = set(e["actor_id"] for e in all_ip_in_window)

                flag = Flag(
                    rule="CREDENTIAL_STUFFING",
                    severity_hint="high" if len(unique_actors) > 5 else "medium",
                    events=[e["event_id"] for e in all_ip_in_window],
                    evidence={
                        "ip": ip,
                        "failed_count": len(window_events),
                        "total_attempts": len(all_ip_in_window),
                        "unique_actors_targeted": len(unique_actors),
                        "actor_ids": list(unique_actors)[:10],  # Cap for readability
                        "window_start": failed[i]["timestamp"],
                        "window_end": failed[j]["timestamp"],
                        "window_minutes": CREDENTIAL_STUFFING_WINDOW_MIN,
                        "user_agents": list(set(
                            e.get("metadata", {}).get("user_agent", "unknown")
                            for e in all_ip_in_window
                        )),
                    },
                    timestamp=failed[i]["timestamp"],
                )
                flags.append(flag)
                break  # One flag per IP is enough

    return flags


def detect_admin_anomaly(events: list[dict]) -> list[Flag]:
    """
    Rule 2: Admin Anomaly Detection
    
    Logic: Flag admin accounts accessing endpoints outside their known set,
    especially during unusual hours (midnight-6am). Also flag activity from
    non-office IPs.
    """
    flags = []

    # Build admin endpoint history from "normal" hours (7am-11pm)
    admin_history: dict[str, set[str]] = defaultdict(set)
    admin_ips: dict[str, set[str]] = defaultdict(set)

    admin_events = [e for e in events if e["actor_id"].startswith("admin_")]

    for evt in admin_events:
        ts = parse_ts(evt["timestamp"])
        if ts.hour not in ADMIN_UNUSUAL_HOURS:
            admin_history[evt["actor_id"]].add(evt["endpoint"])
            admin_ips[evt["actor_id"]].add(evt["ip"])

    # Now look for anomalies
    for evt in admin_events:
        ts = parse_ts(evt["timestamp"])
        actor = evt["actor_id"]
        endpoint = evt["endpoint"]
        ip = evt["ip"]

        anomalies = []

        # Check for unusual endpoint
        known = admin_history.get(actor, set()) | ADMIN_KNOWN_ENDPOINTS
        if endpoint not in known:
            anomalies.append(f"new_endpoint:{endpoint}")

        # Check for unusual hours
        if ts.hour in ADMIN_UNUSUAL_HOURS:
            anomalies.append(f"unusual_hour:{ts.hour}:00")

        # Check for unusual IP
        known_ips = admin_ips.get(actor, set())
        if known_ips and ip not in known_ips:
            anomalies.append(f"unusual_ip:{ip}")

        if len(anomalies) >= 2:  # Need at least 2 anomaly signals
            # Collect all events from this admin in this suspicious session
            session_events = [
                e for e in admin_events
                if e["actor_id"] == actor
                and e["timestamp"] == evt["timestamp"]
            ]

            flag = Flag(
                rule="ADMIN_ANOMALY",
                severity_hint="critical" if "new_endpoint" in str(anomalies) else "high",
                events=[evt["event_id"]],
                evidence={
                    "admin_id": actor,
                    "endpoint": endpoint,
                    "ip": ip,
                    "timestamp_hour": ts.hour,
                    "anomaly_signals": anomalies,
                    "known_endpoints": list(known)[:8],
                    "known_ips": list(known_ips)[:5],
                    "session_metadata": evt.get("metadata", {}),
                },
                timestamp=evt["timestamp"],
            )
            flags.append(flag)

    return flags


def detect_merchant_refund_spike(events: list[dict]) -> list[Flag]:
    """
    Rule 3: Merchant Refund Spike Detection
    
    Logic: For each merchant, compare refund rate in the last 30 minutes
    vs their rolling 24h baseline. Flag if ratio >= 5x.
    """
    flags = []

    # Filter to refund events
    refund_events = [e for e in events if e["action"] == "refund_issued"]
    if not refund_events:
        return flags

    refund_events.sort(key=lambda e: e["timestamp"])

    # Group refunds by actor
    actor_refunds: dict[str, list[dict]] = defaultdict(list)
    for evt in refund_events:
        actor_refunds[evt["actor_id"]].append(evt)

    for actor, refunds in actor_refunds.items():
        if len(refunds) < 3:  # Need minimum activity to detect a spike
            continue

        refunds.sort(key=lambda e: e["timestamp"])

        # Use the latest event's time as "now"
        latest_ts = parse_ts(refunds[-1]["timestamp"])
        window = timedelta(minutes=MERCHANT_DRIFT_WINDOW_MIN)
        baseline_window = timedelta(hours=MERCHANT_DRIFT_BASELINE_HRS)

        # Recent refunds (last 30 min)
        recent = [r for r in refunds if latest_ts - parse_ts(r["timestamp"]) <= window]

        # Baseline refunds (24h, excluding the recent window)
        baseline = [
            r for r in refunds
            if latest_ts - parse_ts(r["timestamp"]) <= baseline_window
            and latest_ts - parse_ts(r["timestamp"]) > window
        ]

        # Calculate rates
        recent_count = len(recent)
        baseline_rate_per_30min = (len(baseline) / (24 * 2)) if baseline else 0.5  # default low baseline

        if baseline_rate_per_30min == 0:
            baseline_rate_per_30min = 0.5  # Avoid division by zero

        ratio = recent_count / baseline_rate_per_30min

        if ratio >= MERCHANT_DRIFT_MULTIPLIER and recent_count >= 5:
            total_amount = sum(r.get("amount", 0) for r in recent)
            baseline_avg_amount = (
                sum(r.get("amount", 0) for r in baseline) / len(baseline)
                if baseline else 0
            )

            flag = Flag(
                rule="MERCHANT_REFUND_SPIKE",
                severity_hint="high" if ratio >= 10 else "medium",
                events=[r["event_id"] for r in recent],
                evidence={
                    "merchant_id": actor,
                    "recent_refund_count": recent_count,
                    "recent_window_minutes": MERCHANT_DRIFT_WINDOW_MIN,
                    "baseline_refund_count": len(baseline),
                    "baseline_window_hours": MERCHANT_DRIFT_BASELINE_HRS,
                    "spike_ratio": round(ratio, 2),
                    "total_refund_amount": round(total_amount, 2),
                    "baseline_avg_amount": round(baseline_avg_amount, 2),
                    "refund_reasons": list(set(
                        r.get("metadata", {}).get("refund_reason", "unspecified")
                        for r in recent
                    )),
                    "has_bulk_metadata": any(
                        r.get("metadata", {}).get("bulk_operation", False)
                        for r in recent
                    ),
                    "batch_ids": list(set(
                        r.get("metadata", {}).get("batch_id", "")
                        for r in recent
                        if r.get("metadata", {}).get("batch_id")
                    )),
                    "consistent_amount": len(set(r.get("amount", 0) for r in recent)) == 1,
                    "ip_addresses": list(set(r["ip"] for r in recent)),
                },
                timestamp=recent[0]["timestamp"],
            )
            flags.append(flag)

    return flags


def run_all_rules(events: list[dict]) -> list[dict]:
    """Run all detection rules and return collected flags."""
    Flag._counter = 0  # Reset counter

    all_flags = []
    all_flags.extend(detect_credential_stuffing(events))
    all_flags.extend(detect_admin_anomaly(events))
    all_flags.extend(detect_merchant_refund_spike(events))

    return [f.to_dict() for f in all_flags]


def main():
    """Standalone test: load events.json and run detector."""
    from pathlib import Path

    events_path = Path(__file__).parent.parent / "data" / "events.json"
    with open(events_path) as f:
        events = json.load(f)

    flags = run_all_rules(events)

    print(f"\n{'='*60}")
    print(f" Stage 1 Detector — {len(flags)} flags raised")
    print(f"{'='*60}\n")

    for flag in flags:
        print(f"  [{flag['severity_hint'].upper():>8}] {flag['flag_id']} — {flag['rule']}")
        print(f"           Events: {len(flag['events'])} | Evidence keys: {list(flag['evidence'].keys())}")
        print()

    return flags


if __name__ == "__main__":
    main()
