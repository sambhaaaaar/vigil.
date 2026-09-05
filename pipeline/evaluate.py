"""
Pipeline Evaluator — Metrics Computation

Computes precision, recall, and false-positive handling quality
against the known ground-truth labels seeded in the synthetic data.
"""

import json
import sys
from pathlib import Path

# Force UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# Ground truth: the attack patterns we seeded
GROUND_TRUTH_ATTACKS = {
    "credential_stuffing": {
        "description": "35+ failed logins from 2-3 IPs across many API keys",
        "expected_rule": "CREDENTIAL_STUFFING",
        "expected_severity": "escalate",
        "actor_pattern": "rzp_key_",
    },
    "admin_anomaly": {
        "description": "admin_04 hitting sensitive endpoints at 3am from VPN",
        "expected_rule": "ADMIN_ANOMALY",
        "expected_severity": "escalate",
        "actor_pattern": "admin_04",
    },
    "merchant_refund_spike": {
        "description": "merchant_042 issuing 18 refunds in 30 minutes (10x baseline)",
        "expected_rule": "MERCHANT_REFUND_SPIKE",
        "expected_severity": "escalate",
        "actor_pattern": "merchant_042",
    },
}

GROUND_TRUTH_FALSE_POSITIVE = {
    "false_positive_benign": {
        "description": "merchant_088 legitimate bulk refund (subscription cancellation batch)",
        "expected_severity": "dismiss",  # or "watch" is acceptable
        "actor_pattern": "merchant_088",
    },
}


def load_data():
    """Load events, flags, and incidents."""
    events_path = PROJECT_ROOT / "data" / "events.json"
    flags_path = PROJECT_ROOT / "output" / "flags.json"
    incidents_path = PROJECT_ROOT / "output" / "incidents.json"

    with open(events_path) as f:
        events = json.load(f)
    with open(flags_path) as f:
        flags = json.load(f)
    with open(incidents_path) as f:
        incidents = json.load(f)

    return events, flags, incidents


def evaluate_detection(events, flags):
    """Evaluate Stage 1 (Detector) performance."""
    print(f"\n{'='*60}")
    print(f"  STAGE 1 — DETECTOR EVALUATION")
    print(f"{'='*60}")

    # Collect ground truth event IDs by attack type
    gt_events = {}
    for evt in events:
        gt = evt.get("_ground_truth", "")
        if gt and gt not in ("normal", "normal_traffic", "normal_baseline"):
            if gt not in gt_events:
                gt_events[gt] = []
            gt_events[gt].append(evt["event_id"])

    # Check which attacks were detected
    detected = {}
    for attack_name, attack_info in GROUND_TRUTH_ATTACKS.items():
        expected_rule = attack_info["expected_rule"]
        matching_flags = [f for f in flags if f["rule"] == expected_rule]

        if matching_flags:
            # Check if flag events overlap with ground truth events
            flagged_events = set()
            for flag in matching_flags:
                flagged_events.update(flag["events"])

            gt_event_set = set(gt_events.get(attack_name, []))
            overlap = flagged_events & gt_event_set
            recall = len(overlap) / len(gt_event_set) if gt_event_set else 0

            detected[attack_name] = {
                "caught": True,
                "flags": [f["flag_id"] for f in matching_flags],
                "events_caught": len(overlap),
                "events_total": len(gt_event_set),
                "event_recall": round(recall, 2),
            }
        else:
            detected[attack_name] = {
                "caught": False,
                "flags": [],
                "events_caught": 0,
                "events_total": len(gt_events.get(attack_name, [])),
                "event_recall": 0.0,
            }

    # Check false positive detection
    fp_info = GROUND_TRUTH_FALSE_POSITIVE["false_positive_benign"]
    fp_flags = [
        f for f in flags
        if any(
            fp_info["actor_pattern"] in str(f.get("evidence", {}))
            for _ in [1]
        )
        or any(
            fp_info["actor_pattern"] in evt_id
            for evt_id in f.get("events", [])
        )
    ]

    # More accurate: check if any flag's evidence mentions merchant_088
    fp_flags_accurate = []
    fp_gt_events = set(gt_events.get("false_positive_benign", []))
    for flag in flags:
        flagged_set = set(flag.get("events", []))
        if flagged_set & fp_gt_events:
            fp_flags_accurate.append(flag)

    fp_detected = len(fp_flags_accurate) > 0

    # Print results
    attacks_caught = sum(1 for d in detected.values() if d["caught"])
    total_attacks = len(GROUND_TRUTH_ATTACKS)
    detection_recall = attacks_caught / total_attacks

    print(f"\n  Attack Detection Recall: {attacks_caught}/{total_attacks} ({detection_recall:.0%})")
    print(f"  False Positive Flagged:  {'Yes' if fp_detected else 'No'}")
    print(f"  Total Flags Raised:      {len(flags)}")
    print()

    print(f"  {'Attack Pattern':<30} {'Caught?':<10} {'Flags':<15} {'Event Recall':<15}")
    print(f"  {'─'*70}")
    for attack_name, info in detected.items():
        caught = "✅ YES" if info["caught"] else "❌ NO"
        flags_str = ", ".join(info["flags"]) if info["flags"] else "—"
        recall_str = f"{info['events_caught']}/{info['events_total']} ({info['event_recall']:.0%})"
        print(f"  {attack_name:<30} {caught:<10} {flags_str:<15} {recall_str}")

    if fp_detected:
        print(f"\n  ⚠ False positive (merchant_088 bulk refund) was flagged by detector.")
        print(f"    This is expected — Stage 2 (copilot) should correctly dismiss it.")
    else:
        print(f"\n  ✓ False positive was not flagged by detector (clean pass).")

    return {
        "detection_recall": detection_recall,
        "attacks_caught": attacks_caught,
        "total_attacks": total_attacks,
        "false_positive_flagged": fp_detected,
        "details": detected,
    }


def evaluate_triage(incidents, flags):
    """Evaluate Stage 2 (Triage Copilot) performance."""
    print(f"\n{'='*60}")
    print(f"  STAGE 2 — TRIAGE COPILOT EVALUATION")
    print(f"{'='*60}")

    results = {}

    for attack_name, attack_info in GROUND_TRUTH_ATTACKS.items():
        expected_severity = attack_info["expected_severity"]
        expected_rule = attack_info["expected_rule"]

        # Find the incident that contains flags from this attack's rule
        matching_flags = [f["flag_id"] for f in flags if f["rule"] == expected_rule]

        matching_incident = None
        for inc in incidents:
            related = set(inc.get("related_flags", []))
            if related & set(matching_flags):
                matching_incident = inc
                break

        if matching_incident:
            actual_severity = matching_incident.get("severity", "unknown")
            correct = actual_severity == expected_severity
            results[attack_name] = {
                "incident_id": matching_incident.get("incident_id"),
                "expected_severity": expected_severity,
                "actual_severity": actual_severity,
                "correct": correct,
                "confidence": matching_incident.get("confidence", 0),
                "explanation_preview": matching_incident.get("explanation", "")[:80],
            }
        else:
            results[attack_name] = {
                "incident_id": None,
                "expected_severity": expected_severity,
                "actual_severity": "not_found",
                "correct": False,
                "confidence": 0,
                "explanation_preview": "No matching incident found",
            }

    # Check false positive handling — look for incident specifically about merchant_088
    fp_result = None
    for inc in incidents:
        inc_json = json.dumps(inc).lower()
        # Must mention merchant_088 explicitly as the primary subject
        is_088_incident = (
            "merchant_088" in inc.get("title", "").lower()
            or "merchant_088" in inc.get("explanation", "").lower()
            or ("088" in inc_json and inc.get("severity") in ("dismiss", "watch"))
        )
        if is_088_incident:
            fp_result = {
                "incident_id": inc.get("incident_id"),
                "severity": inc.get("severity"),
                "confidence": inc.get("confidence"),
                "correctly_handled": inc.get("severity") in ("dismiss", "watch"),
                "explanation_preview": inc.get("explanation", "")[:80],
            }
            break
    
    # Fallback: if no 088-specific incident, check if any dismiss/watch incident is the FP
    if fp_result is None:
        for inc in incidents:
            if inc.get("severity") in ("dismiss", "watch"):
                inc_json = json.dumps(inc).lower()
                if "batch" in inc_json and "subscription" in inc_json:
                    fp_result = {
                        "incident_id": inc.get("incident_id"),
                        "severity": inc.get("severity"),
                        "confidence": inc.get("confidence"),
                        "correctly_handled": True,
                        "explanation_preview": inc.get("explanation", "")[:80],
                    }
                    break

    # Print results
    correct_count = sum(1 for r in results.values() if r["correct"])
    total = len(results)
    accuracy = correct_count / total if total > 0 else 0

    print(f"\n  Triage Accuracy: {correct_count}/{total} ({accuracy:.0%})")
    print()

    print(f"  {'Attack':<28} {'Expected':<12} {'Actual':<12} {'Correct?':<10} {'Conf':>6}")
    print(f"  {'─'*70}")
    for attack_name, info in results.items():
        correct_str = "✅" if info["correct"] else "❌"
        conf = f"{info['confidence']:.2f}" if isinstance(info["confidence"], (int, float)) else "?"
        print(f"  {attack_name:<28} {info['expected_severity']:<12} {info['actual_severity']:<12} {correct_str:<10} {conf:>6}")

    print()
    if fp_result:
        correct_str = "✅" if fp_result["correctly_handled"] else "❌"
        print(f"  False Positive Handling:")
        print(f"    {correct_str} merchant_088 bulk refund → severity={fp_result['severity']}, "
              f"confidence={fp_result.get('confidence', '?')}")
        print(f"    Explanation: {fp_result['explanation_preview']}...")
    else:
        print(f"  ℹ False positive was not flagged → correctly not present in triage results")
        fp_result = {"correctly_handled": True, "severity": "not_flagged"}

    return {
        "triage_accuracy": accuracy,
        "correct_count": correct_count,
        "total": total,
        "false_positive_handled": fp_result.get("correctly_handled", False) if fp_result else True,
        "details": results,
        "false_positive": fp_result,
    }


def compute_precision_recall(detection_results, triage_results, incidents):
    """Compute overall precision and recall."""
    print(f"\n{'='*60}")
    print(f"  OVERALL METRICS")
    print(f"{'='*60}")

    # True positives: real attacks correctly escalated
    tp = sum(
        1 for r in triage_results["details"].values()
        if r["correct"] and r["actual_severity"] == "escalate"
    )

    # False negatives: real attacks missed or incorrectly triaged
    fn = sum(
        1 for r in triage_results["details"].values()
        if not r["correct"]
    )

    # False positives: benign activity incorrectly escalated
    fp = 0
    if triage_results.get("false_positive"):
        if not triage_results["false_positive"].get("correctly_handled", True):
            fp = 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n  True Positives:   {tp}")
    print(f"  False Negatives:  {fn}")
    print(f"  False Positives:  {fp}")
    print()
    print(f"  ┌─────────────┬────────┐")
    print(f"  │ Precision   │ {precision:>5.1%} │")
    print(f"  │ Recall      │ {recall:>5.1%} │")
    print(f"  │ F1 Score    │ {f1:>5.1%} │")
    print(f"  └─────────────┴────────┘")

    return {
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1_score": round(f1, 3),
    }


def generate_metrics_markdown(detection, triage, overall):
    """Generate a markdown metrics table for the README."""
    md = []
    md.append("## 📊 Evaluation Metrics\n")
    md.append("### Overall Performance\n")
    md.append("| Metric | Value |")
    md.append("|--------|-------|")
    md.append(f"| Precision | {overall['precision']:.1%} |")
    md.append(f"| Recall | {overall['recall']:.1%} |")
    md.append(f"| F1 Score | {overall['f1_score']:.1%} |")
    md.append(f"| True Positives | {overall['true_positives']} |")
    md.append(f"| False Positives | {overall['false_positives']} |")
    md.append(f"| False Negatives | {overall['false_negatives']} |")
    md.append("")

    md.append("### Detection Results (Stage 1)\n")
    md.append(f"Detection recall: **{detection['attacks_caught']}/{detection['total_attacks']}** attacks caught\n")
    md.append("| Attack Pattern | Detected | Event Recall |")
    md.append("|----------------|----------|--------------|")
    for name, info in detection["details"].items():
        status = "✅" if info["caught"] else "❌"
        recall = f"{info['event_recall']:.0%}"
        md.append(f"| {name} | {status} | {recall} |")
    md.append("")

    md.append("### Triage Results (Stage 2)\n")
    md.append(f"Triage accuracy: **{triage['correct_count']}/{triage['total']}**\n")
    md.append("| Attack | Expected | Actual | Correct | Confidence |")
    md.append("|--------|----------|--------|---------|------------|")
    for name, info in triage["details"].items():
        status = "✅" if info["correct"] else "❌"
        conf = f"{info['confidence']:.2f}" if isinstance(info["confidence"], (int, float)) else "?"
        md.append(f"| {name} | {info['expected_severity']} | {info['actual_severity']} | {status} | {conf} |")
    md.append("")

    if triage.get("false_positive"):
        fp = triage["false_positive"]
        status = "✅ Correctly handled" if fp.get("correctly_handled") else "❌ Incorrectly escalated"
        md.append(f"### False Positive Handling\n")
        md.append(f"**Deliberate false positive** (merchant_088 bulk refund): {status}\n")
        if fp.get("severity"):
            md.append(f"- Copilot severity: `{fp['severity']}`")
        if fp.get("confidence"):
            md.append(f"- Copilot confidence: `{fp['confidence']}`")
        if fp.get("explanation_preview"):
            md.append(f"- Explanation: *{fp['explanation_preview']}...*")
    md.append("")

    md.append("### What We Got Wrong (Honest Assessment)\n")
    md.append("| Issue | Details |")
    md.append("|-------|---------|")

    wrong_items = []
    for name, info in triage["details"].items():
        if not info["correct"]:
            wrong_items.append(f"| {name} triage | Expected `{info['expected_severity']}`, "
                             f"got `{info['actual_severity']}` (confidence: {info.get('confidence', '?')}) |")

    if triage.get("false_positive") and not triage["false_positive"].get("correctly_handled", True):
        wrong_items.append("| False positive | Bulk refund incorrectly escalated — "
                          "copilot did not recognize batch metadata |")

    if not wrong_items:
        md.append("| — | All seeded patterns correctly identified and triaged ✅ |")
    else:
        md.extend(wrong_items)

    return "\n".join(md)


def main():
    """Run full evaluation."""
    events, flags, incidents = load_data()

    detection_results = evaluate_detection(events, flags)
    triage_results = evaluate_triage(incidents, flags)
    overall = compute_precision_recall(detection_results, triage_results, incidents)

    # Save metrics markdown
    metrics_md = generate_metrics_markdown(detection_results, triage_results, overall)
    metrics_path = PROJECT_ROOT / "output" / "metrics.md"
    with open(metrics_path, "w", encoding="utf-8") as f:
        f.write(metrics_md)
    print(f"\n  ✓ Metrics markdown saved → {metrics_path}")

    # Save full evaluation results
    eval_results = {
        "detection": detection_results,
        "triage": triage_results,
        "overall": overall,
    }
    eval_path = PROJECT_ROOT / "output" / "evaluation.json"
    with open(eval_path, "w", encoding="utf-8") as f:
        json.dump(eval_results, f, indent=2, default=str)
    print(f"  ✓ Full evaluation saved → {eval_path}")

    return eval_results


if __name__ == "__main__":
    main()
