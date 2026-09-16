"""Tests for the shared Autorouter recent-routes client.

The normalisation is pure, so the payload quirks are covered without a network
or a database.
"""

from __future__ import annotations

import pytest

from flyfun_common.autorouter import (
    AutorouterNotLinked,
    AutorouterUnavailable,
    parse_recent_routes,
)


def _entry(**overrides) -> dict:
    entry = {
        "routeid": 1234,
        "departure": "EGTF",
        "destination": "LFRM",
        "departurename": "Fairoaks",
        "destinationname": "Le Mans",
        "departuretime": 1_767_225_600,
        "fplan": "(FPL-GABCD-VG\n-P28A/L-SDFGLOR/S\n-EGTF1000\n-N0110VFR LFRM\n-LFRM0130)",
        "routedistance": 210,
        "aircraftdescription": "PA28 Warrior",
        "callsign": "GABCD",
    }
    entry.update(overrides)
    return entry


def test_parses_a_bare_list():
    routes = parse_recent_routes([_entry()])
    assert len(routes) == 1
    route = routes[0]
    assert route.routeid == "1234"
    assert route.departure == "EGTF"
    assert route.destination == "LFRM"
    assert route.route_distance_nm == 210
    assert route.departure_time == "2026-01-01T00:00:00+00:00"


def test_parses_a_wrapped_list():
    """The endpoint has been seen wrapping the list in an object."""
    routes = parse_recent_routes({"logs": [_entry()], "count": 1})
    assert [r.routeid for r in routes] == ["1234"]


def test_drops_rows_missing_what_an_import_needs():
    rows = [
        _entry(),
        _entry(routeid=2, fplan=""),  # nothing to import
        _entry(routeid=3, destination=""),  # nothing to render
        "not a dict",
    ]
    routes = parse_recent_routes(rows)
    assert [r.routeid for r in routes] == ["1234"]


def test_missing_optional_fields_are_none_not_empty_strings():
    routes = parse_recent_routes(
        [_entry(aircraftdescription="", callsign="", routedistance="n/a", departuretime=0)]
    )
    route = routes[0]
    assert route.aircraft_description is None
    assert route.callsign is None
    assert route.route_distance_nm is None
    assert route.departure_time is None


def test_unusable_payload_shapes_raise():
    with pytest.raises(AutorouterUnavailable):
        parse_recent_routes("nope")
    with pytest.raises(AutorouterUnavailable):
        parse_recent_routes({"count": 1})


def test_not_linked_and_unavailable_are_distinct_errors():
    """The endpoint maps them to different statuses, so they must not merge."""
    assert not issubclass(AutorouterNotLinked, AutorouterUnavailable)
    assert not issubclass(AutorouterUnavailable, AutorouterNotLinked)


def test_known_wrapper_key_wins_over_an_unrelated_list():
    """A pagination list added alongside the routes must not be read as routes."""
    routes = parse_recent_routes({"links": [], "logs": [_entry()]})
    assert [r.routeid for r in routes] == ["1234"]


def test_upstream_shape_problems_are_distinguishable_from_unreachable():
    """The two map to different 502 details, so a client can tell them apart."""
    with pytest.raises(AutorouterUnavailable) as excinfo:
        parse_recent_routes({"count": 1})
    assert excinfo.value.detail == "autorouter_upstream_error"


def test_status_answers_from_stored_credentials_without_calling_autorouter(monkeypatch):
    """A client asks this on every screen offering Autorouter, so it must not
    cost an upstream round trip."""
    import httpx

    from flyfun_common.autorouter import create_autorouter_routes_router

    def _fail(*args, **kwargs):
        raise AssertionError("status must not call Autorouter")

    monkeypatch.setattr(httpx, "get", _fail)

    router = create_autorouter_routes_router(token_loader=lambda db, uid: "tok")
    paths = {route.path for route in router.routes}
    assert paths == {"/api/autorouter/status", "/api/autorouter/routes"}
