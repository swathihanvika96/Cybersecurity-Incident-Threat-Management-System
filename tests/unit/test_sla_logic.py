from datetime import datetime, timedelta
from types import SimpleNamespace as NS

from app.services.sla_service import compute_state

CREATED = datetime(2026, 1, 1, 12, 0)


def sla(ack=None, inv=None, res=None, ack_min=15, inv_min=60, res_min=240):
    return NS(ack_deadline=CREATED + timedelta(minutes=ack_min), investigation_deadline=CREATED + timedelta(minutes=inv_min),
              resolution_deadline=CREATED + timedelta(minutes=res_min), acknowledged_at=ack,
              investigation_started_at=inv, resolved_at=res)


def at(minutes):
    return CREATED + timedelta(minutes=minutes)


def test_on_track_early():
    assert compute_state(sla(), CREATED, at(1), 0.25).status == "on_track"


def test_at_risk_when_deadline_close():
    assert compute_state(sla(ack=at(1), inv=at(5)), CREATED, at(200), 0.25).status == "at_risk"


def test_unacknowledged_past_deadline_is_breached():
    state = compute_state(sla(), CREATED, at(20), 0.25)
    assert state.status == "breached" and state.ack_breached and not state.resolution_breached


def test_late_acknowledgment_stays_breached():
    assert compute_state(sla(ack=at(30), inv=at(40), res=at(100)), CREATED, at(101), 0.25).ack_breached


def test_resolved_in_time_is_met():
    state = compute_state(sla(ack=at(5), inv=at(20), res=at(100)), CREATED, at(500), 0.25)
    assert state.status == "met" and state.flags == (False, False, False)


def test_resolved_late_is_breached():
    assert compute_state(sla(ack=at(5), inv=at(20), res=at(300)), CREATED, at(301), 0.25).resolution_breached
