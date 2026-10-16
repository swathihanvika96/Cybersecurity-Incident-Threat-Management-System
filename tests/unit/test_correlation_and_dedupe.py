from datetime import datetime, timedelta
from types import SimpleNamespace as NS

from app.services.alert_service import compute_fingerprint
from app.services.correlation_service import cluster_alerts

T0 = datetime(2026, 1, 1, 12, 0)


def alert(i, minutes, asset=1, category="malware"):
    return NS(id=i, asset_id=asset, category=category, detected_at=T0 + timedelta(minutes=minutes))


def test_three_alerts_inside_window_form_one_cluster():
    clusters = cluster_alerts([alert(1, 0), alert(2, 30), alert(3, 60)], window_minutes=45, min_alerts=3)
    assert [[a.id for a in c] for c in clusters] == [[1, 2, 3]]


def test_gap_larger_than_window_splits_cluster():
    assert cluster_alerts([alert(1, 0), alert(2, 10), alert(3, 200)], 45, 3) == []


def test_below_minimum_is_not_a_cluster():
    assert cluster_alerts([alert(1, 0), alert(2, 5)], 60, 3) == []


def test_different_asset_or_category_never_mix():
    alerts = [alert(1, 0), alert(2, 5, asset=2), alert(3, 10, category="phishing"), alert(4, 15)]
    assert cluster_alerts(alerts, 60, 3) == []


def test_input_order_is_irrelevant():
    clusters = cluster_alerts([alert(3, 60), alert(1, 0), alert(2, 30)], 45, 3)
    assert [a.id for a in clusters[0]] == [1, 2, 3]


def test_fingerprint_normalises_title():
    assert compute_fingerprint(1, "malware", "SIEM", "  Ransomware   Detected ") == \
        compute_fingerprint(1, "malware", "SIEM", "ransomware detected")


def test_fingerprint_differs_by_asset_source_and_category():
    base = compute_fingerprint(1, "malware", "SIEM", "x")
    assert base != compute_fingerprint(2, "malware", "SIEM", "x")
    assert base != compute_fingerprint(1, "malware", "EDR", "x")
    assert base != compute_fingerprint(1, "phishing", "SIEM", "x")
