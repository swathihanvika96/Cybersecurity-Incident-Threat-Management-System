import pytest

from app.services.risk_service import compute_risk, level_for_score
from app.services.vulnerability_service import severity_from_cvss


def test_maximum_risk_is_100_critical():
    assert compute_risk("critical", "critical", 10.0) == (100.0, "critical")


def test_minimum_risk_is_low():
    score, level = compute_risk("low", "low", 0.0)
    assert 0 < score < 25 and level == "low"


def test_criticality_raises_score_for_same_vulnerability():
    assert compute_risk("critical", "high", 8.0)[0] > compute_risk("medium", "high", 8.0)[0]


def test_cvss_raises_score():
    assert compute_risk("high", "high", 9.0)[0] > compute_risk("high", "high", 5.0)[0]


@pytest.mark.parametrize("score,level", [(0, "low"), (24.99, "low"), (25, "medium"), (49.99, "medium"),
                                         (50, "high"), (74.99, "high"), (75, "critical"), (100, "critical")])
def test_level_bands(score, level):
    assert level_for_score(score) == level


@pytest.mark.parametrize("args", [("bogus", "high", 5), ("high", "bogus", 5), ("high", "high", 10.1),
                                  ("high", "high", -1)])
def test_invalid_inputs_rejected(args):
    with pytest.raises(ValueError):
        compute_risk(*args)


@pytest.mark.parametrize("cvss,sev", [(0, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"), (7.0, "high"),
                                      (8.9, "high"), (9.0, "critical"), (10, "critical")])
def test_severity_from_cvss(cvss, sev):
    assert severity_from_cvss(cvss) == sev
