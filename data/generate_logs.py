"""
Synthetic Razorpay Event Log Generator
Generates ~250 payment/API events with 4 seeded patterns:
  1. Credential stuffing (35+ failed logins from few IPs)
  2. Admin anomaly (unusual endpoint + time)
  3. Merchant refund spike (10x baseline)
  4. False positive — legitimate bulk refund operation
"""

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

# ─── Constants ──────────────────────────────────────────────────────────
BASE_TIME = datetime(2026, 9, 4, 0, 0, 0, tzinfo=timezone.utc)

MERCHANT_IDS = [f"merchant_{str(i).zfill(3)}" for i in range(1, 21)]
ADMIN_IDS = [f"admin_{str(i).zfill(2)}" for i in range(1, 6)]
API_KEYS = [f"rzp_key_{uuid.uuid4().hex[:12]}" for _ in range(30)]

NORMAL_ENDPOINTS = [
    "/v1/payments",
    "/v1/payments/capture",
    "/v1/refunds",
    "/v1/orders",
    "/v1/customers",
    "/v1/invoices",
    "/v1/settlements",
]

ADMIN_NORMAL_ENDPOINTS = [
    "/admin/dashboard",
    "/admin/merchants",
    "/admin/reports",
    "/admin/support-tickets",
]

ADMIN_SENSITIVE_ENDPOINTS = [
    "/v1/settlements/config",
    "/admin/merchant-controls",
    "/admin/api-keys/rotate-all",
    "/admin/risk-rules/override",
]

NORMAL_IPS = [f"103.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(40)]
ATTACK_IPS = ["45.33.32.156", "185.220.101.42", "91.240.118.73"]

ACTIONS = {
    "/v1/payments": ["api_call"],
    "/v1/payments/capture": ["api_call"],
    "/v1/refunds": ["refund_issued"],
    "/v1/orders": ["api_call"],
    "/v1/customers": ["api_call"],
    "/v1/invoices": ["api_call"],
    "/v1/settlements": ["api_call"],
    "/admin/dashboard": ["page_view"],
    "/admin/merchants": ["page_view"],
    "/admin/reports": ["page_view"],
    "/admin/support-tickets": ["page_view"],
}

event_counter = 0


def make_event(
    timestamp, actor_id, action, endpoint, ip, status,
    amount=None, metadata=None, ground_truth=None,
):
    global event_counter
    event_counter += 1
    evt = {
        "event_id": f"evt_{str(event_counter).zfill(4)}",
        "timestamp": timestamp.isoformat(),
        "actor_id": actor_id,
        "action": action,
        "endpoint": endpoint,
        "ip": ip,
        "status": status,
    }
    if amount is not None:
        evt["amount"] = amount
    if metadata:
        evt["metadata"] = metadata
    if ground_truth:
        evt["_ground_truth"] = ground_truth
    return evt


def generate_normal_traffic(start, end, count=180):
    """Generate realistic baseline Razorpay API traffic."""
    events = []
    duration = (end - start).total_seconds()

    for _ in range(count):
        ts = start + timedelta(seconds=random.uniform(0, duration))
        actor = random.choice(MERCHANT_IDS)
        endpoint = random.choice(NORMAL_ENDPOINTS)
        action = random.choice(ACTIONS.get(endpoint, ["api_call"]))
        ip = random.choice(NORMAL_IPS)
        status = random.choices(["success", "failed"], weights=[95, 5])[0]
        amount = None
        if endpoint in ["/v1/payments", "/v1/payments/capture"]:
            amount = round(random.uniform(100, 50000), 2)
        elif endpoint == "/v1/refunds":
            amount = round(random.uniform(50, 5000), 2)

        events.append(make_event(ts, actor, action, endpoint, ip, status))

    # Normal admin activity during business hours (9am-6pm)
    for _ in range(15):
        hour = random.randint(9, 17)
        ts = start + timedelta(
            hours=hour,
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )
        admin = random.choice(ADMIN_IDS[:3])  # Only first 3 admins are "normal"
        endpoint = random.choice(ADMIN_NORMAL_ENDPOINTS)
        ip = random.choice(NORMAL_IPS[:5])  # Admins use office IPs
        events.append(
            make_event(ts, admin, "page_view", endpoint, ip, "success",
                       ground_truth="normal")
        )

    # A few normal merchant logins
    for _ in range(10):
        ts = start + timedelta(
            hours=random.randint(8, 20),
            minutes=random.randint(0, 59),
        )
        actor = random.choice(MERCHANT_IDS + API_KEYS[:10])
        ip = random.choice(NORMAL_IPS)
        status = random.choices(["success", "failed"], weights=[90, 10])[0]
        events.append(
            make_event(ts, actor, "login_attempt", "/v1/auth/login", ip, status,
                       ground_truth="normal")
        )

    return events


def seed_credential_stuffing(base_time):
    """
    Attack Pattern 1: Credential stuffing
    35+ failed logins from 2-3 IPs across many actor_ids in a 10-minute window.
    """
    events = []
    window_start = base_time + timedelta(hours=2, minutes=10)

    for i in range(35):
        ts = window_start + timedelta(seconds=random.randint(0, 600))
        actor = random.choice(API_KEYS)  # Trying many different API keys
        ip = random.choice(ATTACK_IPS[:2])  # From only 2 IPs
        events.append(
            make_event(
                ts, actor, "login_attempt", "/v1/auth/login", ip, "failed",
                metadata={"user_agent": "python-requests/2.28.0", "attempt_type": "api_key_auth"},
                ground_truth="credential_stuffing",
            )
        )

    # A few successes mixed in (attacker got lucky on some)
    for i in range(3):
        ts = window_start + timedelta(seconds=random.randint(300, 600))
        actor = random.choice(API_KEYS[:3])
        ip = ATTACK_IPS[0]
        events.append(
            make_event(
                ts, actor, "login_attempt", "/v1/auth/login", ip, "success",
                metadata={"user_agent": "python-requests/2.28.0"},
                ground_truth="credential_stuffing",
            )
        )

    return events


def seed_admin_anomaly(base_time):
    """
    Attack Pattern 2: Admin anomaly
    admin_04 (rarely active) hitting sensitive endpoints at 3am.
    """
    events = []
    anomaly_time = base_time + timedelta(hours=3, minutes=5)
    admin = "admin_04"
    ip = "178.62.45.91"  # Unusual IP, not from the office pool

    for i, endpoint in enumerate(ADMIN_SENSITIVE_ENDPOINTS):
        ts = anomaly_time + timedelta(minutes=i * 2, seconds=random.randint(0, 30))
        events.append(
            make_event(
                ts, admin, "admin_action", endpoint, ip, "success",
                metadata={"session_origin": "vpn_external", "geo": "unknown"},
                ground_truth="admin_anomaly",
            )
        )

    # admin_04 also rotates API keys — very suspicious
    ts = anomaly_time + timedelta(minutes=10)
    events.append(
        make_event(
            ts, admin, "key_rotated", "/admin/api-keys/rotate-all", ip, "success",
            metadata={"keys_affected": 12, "session_origin": "vpn_external"},
            ground_truth="admin_anomaly",
        )
    )

    return events


def seed_merchant_refund_spike(base_time):
    """
    Attack Pattern 3: Merchant refund spike
    merchant_042 issues 18 refunds in 30 minutes (baseline is ~1-2/day).
    """
    events = []

    # First, establish merchant_042's normal baseline: 2 refunds earlier in the day
    for i in range(2):
        ts = base_time + timedelta(hours=random.randint(9, 14), minutes=random.randint(0, 59))
        events.append(
            make_event(
                ts, "merchant_042", "refund_issued", "/v1/refunds", 
                random.choice(NORMAL_IPS), "success",
                amount=round(random.uniform(200, 2000), 2),
                ground_truth="normal_baseline",
            )
        )

    # Now the spike: 18 refunds in 30 minutes at 7pm
    spike_start = base_time + timedelta(hours=19, minutes=0)
    for i in range(18):
        ts = spike_start + timedelta(minutes=random.randint(0, 30), seconds=random.randint(0, 59))
        events.append(
            make_event(
                ts, "merchant_042", "refund_issued", "/v1/refunds",
                NORMAL_IPS[7],  # Same merchant IP
                "success",
                amount=round(random.uniform(1000, 15000), 2),
                metadata={"refund_reason": random.choice(["customer_request", "order_cancelled", "duplicate_payment"])},
                ground_truth="merchant_refund_spike",
            )
        )

    return events


def seed_false_positive(base_time):
    """
    False Positive: Legitimate bulk refund operation by merchant_088.
    Looks suspicious (12 refunds in quick succession) but is a scheduled
    bulk processing operation with consistent amounts and metadata.
    """
    events = []
    bulk_start = base_time + timedelta(hours=14, minutes=30)

    for i in range(12):
        ts = bulk_start + timedelta(seconds=i * 15)  # Every 15 seconds — clearly automated
        events.append(
            make_event(
                ts, "merchant_088", "refund_issued", "/v1/refunds",
                NORMAL_IPS[2],  # Consistent office IP
                "success",
                amount=499.00,  # Same amount every time — subscription refund batch
                metadata={
                    "bulk_operation": True,
                    "batch_id": "BATCH-20260904-001",
                    "refund_reason": "subscription_cancellation_batch",
                    "processor": "automated_batch_system",
                },
                ground_truth="false_positive_benign",
            )
        )

    # Also add some normal history for merchant_088 (active merchant)
    for i in range(5):
        ts = base_time + timedelta(hours=random.randint(10, 16), minutes=random.randint(0, 59))
        events.append(
            make_event(
                ts, "merchant_088", "api_call", "/v1/payments",
                NORMAL_IPS[2], "success",
                amount=round(random.uniform(499, 2000), 2),
                ground_truth="normal",
            )
        )

    return events


def generate_all():
    """Generate the complete synthetic dataset."""
    day_start = BASE_TIME
    day_end = BASE_TIME + timedelta(hours=23, minutes=59)

    all_events = []
    all_events.extend(generate_normal_traffic(day_start, day_end))
    all_events.extend(seed_credential_stuffing(BASE_TIME))
    all_events.extend(seed_admin_anomaly(BASE_TIME))
    all_events.extend(seed_merchant_refund_spike(BASE_TIME))
    all_events.extend(seed_false_positive(BASE_TIME))

    # Sort by timestamp
    all_events.sort(key=lambda e: e["timestamp"])

    # Re-number event IDs after sorting
    for i, evt in enumerate(all_events, 1):
        evt["event_id"] = f"evt_{str(i).zfill(4)}"

    return all_events


def main():
    events = generate_all()

    output_path = Path(__file__).parent / "events.json"
    with open(output_path, "w") as f:
        json.dump(events, f, indent=2)

    # Print summary
    print(f"Generated {len(events)} events -> {output_path}")

    ground_truth_counts = {}
    for evt in events:
        gt = evt.get("_ground_truth", "normal_traffic")
        ground_truth_counts[gt] = ground_truth_counts.get(gt, 0) + 1

    print("\nGround truth breakdown:")
    for gt, count in sorted(ground_truth_counts.items()):
        print(f"  {gt}: {count}")


if __name__ == "__main__":
    main()
