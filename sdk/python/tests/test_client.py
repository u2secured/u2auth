"""Tests for u2auth.client using a real HTTP mock server."""

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Any, Dict

import pytest
from u2auth.client import Client, U2AuthError


def make_handler(
    status: int,
    body: Any,
    *,
    assert_method: str = None,
    assert_path: str = None,
    assert_query: Dict[str, str] = None,
    assert_auth: str = None,
    capture: dict = None,
    captures: list = None,
) -> type:
    """assert_path matches the request's bare path (no query string).

    assert_query, when given, asserts the query string decodes to exactly
    those key/value pairs — no more, no fewer — independent of the order
    the keys were sent in. keep_blank_values=True so a key sent as
    "cursor=" (present but empty) is still visible rather than silently
    dropped, keeping absence assertions genuinely absence-checking.

    capture holds only the LAST request. captures, when given, appends one
    {"body", "headers"} entry per request instead — the retry tests need to
    compare what the first call sent against what the second one sent, which
    a single overwritten dict cannot show.
    """

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # silence

        def _respond(self):
            if assert_method:
                assert self.command == assert_method, f"expected {assert_method}, got {self.command}"
            split = urllib.parse.urlsplit(self.path)
            if assert_path is not None:
                assert split.path == assert_path, f"expected path {assert_path}, got {split.path}"
            if assert_query is not None:
                actual = urllib.parse.parse_qs(split.query, keep_blank_values=True)
                expected = {k: [v] for k, v in assert_query.items()}
                assert actual == expected, f"expected query {expected}, got {actual}"
            if assert_auth:
                assert self.headers.get("Authorization") == assert_auth

            if (capture is not None or captures is not None) and self.command in ("POST", "PUT"):
                length = int(self.headers.get("Content-Length", 0))
                data = self.rfile.read(length)
                parsed = json.loads(data) if data else {}
                # Headers recorded alongside body so callers can assert on
                # them (e.g. Idempotency-Key) without a separate fixture.
                headers = dict(self.headers)
                if capture is not None:
                    capture["body"] = parsed
                    capture["headers"] = headers
                if captures is not None:
                    captures.append({"body": parsed, "headers": headers})

            # 204 carries no body — the enrolment-delete path relies on this.
            if status == 204:
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self._respond()

        def do_POST(self):
            self._respond()

        def do_DELETE(self):
            self._respond()

    return Handler


class MockServer:
    """Serves `requests` requests (default 1) then stops.

    The retry tests need two, against the SAME base URL: a client that only
    ever sends one request cannot be shown to send the same key twice.
    """

    def __init__(self, handler, requests: int = 1):
        self.server = HTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self._serve, args=(requests,))
        self.thread.daemon = True
        self.thread.start()

    def _serve(self, n: int):
        for _ in range(n):
            self.server.handle_request()

    def stop(self):
        self.server.server_close()


class TestVerifyTOTP:
    def test_valid_true(self):
        srv = MockServer(
            make_handler(200, {"valid": True},
                         assert_method="POST",
                         assert_path="/api/v1/sdk/totp/verify",
                         assert_auth="Bearer rka_test")
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.verify_totp("MYSECRET", "123456")
        assert result["valid"] is True
        srv.stop()

    def test_valid_false(self):
        srv = MockServer(make_handler(200, {"valid": False}))
        client = Client("rka_test", base_url=srv.url)
        result = client.verify_totp("MYSECRET", "000000")
        assert result["valid"] is False
        srv.stop()

    def test_api_error_raises(self):
        srv = MockServer(
            make_handler(401, {"error": {"code": "UNAUTHORIZED", "message": "bad key"}})
        )
        client = Client("rka_bad", base_url=srv.url)
        with pytest.raises(U2AuthError) as exc_info:
            client.verify_totp("SECRET", "123")
        err = exc_info.value
        assert err.status_code == 401
        assert err.code == "UNAUTHORIZED"
        srv.stop()


class TestRequestPush:
    def test_returns_result(self):
        capture = {}
        srv = MockServer(
            make_handler(200, {
                "approval_id": "apr_abc",
                "status": "pending",
                "expires_at": "2026-06-01T12:00:00Z",
            }, assert_path="/api/v1/sdk/push/request", capture=capture)
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.request_push("user@example.com", "Login from Chrome")
        assert result["approval_id"] == "apr_abc"
        assert result["status"] == "pending"
        assert capture["body"]["user_identifier"] == "user@example.com"
        srv.stop()

    def test_forwards_options(self):
        capture = {}
        srv = MockServer(
            make_handler(200, {
                "approval_id": "apr_xyz",
                "status": "pending",
                "expires_at": "2026-06-01T12:00:00Z",
            }, capture=capture)
        )
        client = Client("rka_test", base_url=srv.url)
        client.request_push(
            "user@example.com", "Test",
            webhook_url="https://example.com/hook", ttl=300
        )
        assert capture["body"]["webhook_url"] == "https://example.com/hook"
        assert capture["body"]["ttl"] == 300
        srv.stop()


class TestRequestPushIdempotency:
    def test_sends_the_idempotency_key_header(self):
        capture = {}
        srv = MockServer(
            make_handler(201, {
                "approval_id": "apr_abc",
                "status": "pending",
                "expires_at": "2026-06-01T12:00:00Z",
            }, assert_path="/api/v1/sdk/push/request", capture=capture)
        )
        client = Client("rka_test", base_url=srv.url)
        client.request_push("alice", "ctx", idempotency_key="k1")
        assert capture["headers"]["Idempotency-Key"] == "k1"
        srv.stop()

    def test_omits_the_header_entirely_when_no_key_given(self):
        # Must be absent, not empty-string — a falsy-but-present header
        # would still reach the server and change its behaviour.
        capture = {}
        srv = MockServer(
            make_handler(201, {
                "approval_id": "apr_abc",
                "status": "pending",
                "expires_at": "2026-06-01T12:00:00Z",
            }, capture=capture)
        )
        client = Client("rka_test", base_url=srv.url)
        client.request_push("alice", "ctx")
        assert "Idempotency-Key" not in capture["headers"]
        srv.stop()

    def test_a_retry_resends_the_same_key_and_the_same_body(self):
        # The retry has to be indistinguishable from the original ON THE WIRE,
        # because that is what the server keys off: the same Idempotency-Key
        # replays only while the request SHAPE also matches, and a shape that
        # drifted between attempts comes back 409 IDEMPOTENCY_KEY_REUSED
        # instead of the original approval. So this asserts on the client's
        # own behaviour across two calls — that it holds no per-call state
        # that mutates or consumes the key, rewrites the body, or short-
        # circuits the second call — rather than on the stub's status code.
        captures = []
        srv = MockServer(
            make_handler(201, {
                "approval_id": "apr_abc",
                "status": "pending",
                "expires_at": "2026-06-01T12:00:00Z",
            }, captures=captures),
            requests=2,
        )
        client = Client("rka_test", base_url=srv.url)
        kwargs = dict(webhook_url="https://example.com/hook", ttl=300,
                      idempotency_key="k1")

        first = client.request_push("alice", "ctx", **kwargs)
        second = client.request_push("alice", "ctx", **kwargs)

        assert len(captures) == 2, "the client must actually issue the retry, not cache the first response"
        assert captures[0]["headers"]["Idempotency-Key"] == "k1"
        assert captures[1]["headers"]["Idempotency-Key"] == "k1", "the retry dropped or changed the key"
        assert captures[0]["body"] == captures[1]["body"], "the retry changed the request shape — the server would 409 it"
        # Both calls surface the server's approval verbatim: on a real replay
        # the second body IS the original approval, so the caller can treat
        # the two results interchangeably.
        assert first["approval_id"] == "apr_abc"
        assert second == first
        srv.stop()

    def test_surfaces_a_reused_key_as_u2autherror(self):
        srv = MockServer(
            make_handler(409, {"error": {"code": "IDEMPOTENCY_KEY_REUSED", "message": "in use"}})
        )
        client = Client("rka_test", base_url=srv.url)
        with pytest.raises(U2AuthError) as exc:
            client.request_push("alice", "ctx", idempotency_key="k1")
        assert exc.value.code == "IDEMPOTENCY_KEY_REUSED"
        assert exc.value.status_code == 409
        srv.stop()

    def test_surfaces_an_overlong_key_as_u2autherror(self):
        srv = MockServer(
            make_handler(400, {"error": {"code": "INVALID_IDEMPOTENCY_KEY", "message": "too long"}})
        )
        client = Client("rka_test", base_url=srv.url)
        with pytest.raises(U2AuthError) as exc:
            client.request_push("alice", "ctx", idempotency_key="k" * 256)
        assert exc.value.code == "INVALID_IDEMPOTENCY_KEY"
        assert exc.value.status_code == 400
        srv.stop()


class TestGetPushStatus:
    def test_returns_status(self):
        srv = MockServer(
            make_handler(200, {"approval_id": "apr_abc123", "status": "approved"},
                         assert_method="GET",
                         assert_path="/api/v1/sdk/push/apr_abc123/status")
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.get_push_status("apr_abc123")
        assert result["status"] == "approved"
        assert result["approval_id"] == "apr_abc123"
        srv.stop()

    def test_not_found_raises(self):
        srv = MockServer(
            make_handler(404, {"error": {"code": "NOT_FOUND", "message": "not found"}})
        )
        client = Client("rka_test", base_url=srv.url)
        with pytest.raises(U2AuthError) as exc_info:
            client.get_push_status("nonexistent")
        assert exc_info.value.status_code == 404
        assert exc_info.value.code == "NOT_FOUND"
        srv.stop()


def _serve(bodies):
    """Server that yields bodies[i] per GET, repeating the last once exhausted."""
    state = {"i": 0}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = bodies[min(state["i"], len(bodies) - 1)]
            state["i"] += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *_):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_address[1]}", srv.shutdown


@pytest.fixture
def client_for():
    """Build a Client whose every GET request (however many arrive) returns
    the same JSON body -- handy for the linked-approvals tests, where
    wait_for_link issues an open-ended number of polling GETs before it
    resolves.

    Yields the builder so a test can call it more than once if it ever needs
    two independently-configured clients; every server started this way is
    torn down when the test ends.
    """
    stops = []

    def _build(body: Dict[str, Any]) -> Client:
        url, stop = _serve([json.dumps(body)])
        stops.append(stop)
        return Client("rka_test", base_url=url)

    yield _build
    for stop in stops:
        stop()


def test_get_push_status_exposes_reason_and_resolved_at():
    url, stop = _serve(['{"approval_id":"ap1","status":"denied","reason":"wrong_number","resolved_at":"2026-01-01T00:00:00Z"}'])
    try:
        st = Client("k", base_url=url).get_push_status("ap1")
        assert st["reason"] == "wrong_number"
        assert st["resolved_at"] == "2026-01-01T00:00:00Z"
    finally:
        stop()


def test_wait_for_approval_polls_until_approved():
    url, stop = _serve([
        '{"approval_id":"ap1","status":"pending"}',
        '{"approval_id":"ap1","status":"pending"}',
        '{"approval_id":"ap1","status":"approved"}',
    ])
    try:
        st = Client("k", base_url=url).wait_for_approval("ap1", timeout=1, interval=0.005)
        assert st["status"] == "approved"
    finally:
        stop()


def test_wait_for_approval_times_out():
    url, stop = _serve(['{"approval_id":"ap1","status":"pending"}'])
    try:
        with pytest.raises(U2AuthError) as ei:
            Client("k", base_url=url).wait_for_approval("ap1", timeout=0.04, interval=0.005)
        assert ei.value.code == "WAIT_TIMEOUT"
    finally:
        stop()


class TestCreatePairingCode:
    def test_posts_identifier_and_returns_code(self):
        capture = {}
        srv = MockServer(
            make_handler(
                201,
                {"code": "3f9a-c210", "expires_at": "2026-07-31T10:20:00Z"},
                assert_method="POST",
                assert_path="/api/v1/sdk/pairing-codes",
                assert_auth="Bearer rka_test",
                capture=capture,
            )
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.create_pairing_code("alice@acme.com")
        assert capture["body"] == {"user_identifier": "alice@acme.com"}
        assert result["code"] == "3f9a-c210"
        assert result["expires_at"] == "2026-07-31T10:20:00Z"
        srv.stop()


class TestListEnrolments:
    def test_default_call_omits_cursor(self):
        # No cursor was passed, so the query must not contain a "cursor" key
        # at all, not "cursor=" — the request should carry only what the
        # caller asked for.
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments",
                assert_query={"limit": "25", "sort": "created_at", "order": "desc"},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.list_enrolments()
        assert result["items"] == []
        srv.stop()

    def test_cursor_included_when_given(self):
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments",
                assert_query={
                    "limit": "50",
                    "sort": "user_identifier",
                    "order": "asc",
                    "cursor": "abc123",
                },
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolments(limit=50, cursor="abc123", sort="user_identifier", order="asc")
        srv.stop()

    def test_returns_next_cursor_for_round_trip(self):
        srv = MockServer(
            make_handler(200, {"items": [], "next_cursor": "next-page-token"})
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.list_enrolments()
        assert result["next_cursor"] == "next-page-token"
        srv.stop()

    def test_zero_limit_is_omitted(self):
        # A limit of 0 means unset, matching Go's rule — it must never
        # reach the server, which would reject it as INVALID_LIMIT.
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments",
                assert_query={"sort": "created_at", "order": "desc"},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolments(limit=0)
        srv.stop()

    def test_negative_limit_is_omitted(self):
        # A negative limit means unset too, same as zero — it must never
        # reach the server, which would reject it as INVALID_LIMIT.
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments",
                assert_query={"sort": "created_at", "order": "desc"},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolments(limit=-1)
        srv.stop()

    def test_last_auth_at_is_none_for_never_authenticated(self):
        srv = MockServer(
            make_handler(200, {
                "items": [{
                    "id": "enr_1",
                    "user_identifier": "alice@acme.com",
                    "created_at": "2026-01-01T00:00:00Z",
                    "last_auth_at": None,
                    "last_auth_outcome": None,
                }],
                "next_cursor": "",
            })
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.list_enrolments()
        enrolment = result["items"][0]
        assert enrolment["last_auth_at"] is None
        assert enrolment["last_auth_outcome"] is None
        srv.stop()


class TestListEnrolmentEvents:
    def test_default_call_omits_cursor(self):
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments/enr_1/events",
                assert_query={"limit": "25"},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolment_events("enr_1")
        srv.stop()

    def test_cursor_included_when_given(self):
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments/enr_1/events",
                assert_query={"limit": "10", "cursor": "xyz"},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolment_events("enr_1", limit=10, cursor="xyz")
        srv.stop()

    def test_zero_limit_is_omitted(self):
        # Same rule as list_enrolments: 0 means unset, never sent.
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments/enr_1/events",
                assert_query={},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolment_events("enr_1", limit=0)
        srv.stop()

    def test_negative_limit_is_omitted(self):
        # Same rule as list_enrolments: a negative limit means unset too.
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments/enr_1/events",
                assert_query={},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolment_events("enr_1", limit=-3)
        srv.stop()

    def test_returns_next_cursor_for_round_trip(self):
        srv = MockServer(
            make_handler(200, {"items": [], "next_cursor": "next-events-token"})
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.list_enrolment_events("enr_1")
        assert result["next_cursor"] == "next-events-token"
        srv.stop()

    def test_place_is_none_for_event_with_no_fix(self):
        srv = MockServer(
            make_handler(200, {
                "items": [{
                    "id": "evt_1",
                    "kind": "push",
                    "outcome": "approved",
                    "created_at": "2026-01-01T00:00:00Z",
                    "place": None,
                    "new_country": False,
                }],
                "next_cursor": "",
            })
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.list_enrolment_events("enr_1")
        assert result["items"][0]["place"] is None
        srv.stop()

    def test_place_region_can_be_empty_string_and_is_distinct_from_none(self):
        srv = MockServer(
            make_handler(200, {
                "items": [{
                    "id": "evt_2",
                    "kind": "push",
                    "outcome": "approved",
                    "created_at": "2026-01-01T00:00:00Z",
                    "place": {"city": "Berlin", "region": "", "country": "DE"},
                    "new_country": False,
                }],
                "next_cursor": "",
            })
        )
        client = Client("rka_test", base_url=srv.url)
        result = client.list_enrolment_events("enr_1")
        place = result["items"][0]["place"]
        assert place is not None
        assert place["region"] == ""
        srv.stop()


class TestListEnrolmentsUserIdentifier:
    def test_user_identifier_included_when_given(self):
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments",
                assert_query={
                    "limit": "25",
                    "sort": "created_at",
                    "order": "desc",
                    "user_identifier": "ada@example.com",
                },
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolments(user_identifier="ada@example.com")
        srv.stop()

    def test_user_identifier_omitted_when_empty(self):
        # Default "" must behave exactly like today: no key on the wire.
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments",
                assert_query={"limit": "25", "sort": "created_at", "order": "desc"},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolments()
        srv.stop()

    def test_user_identifier_of_literal_zero_is_not_treated_as_empty(self):
        # "0" is a legitimate developer-chosen identifier (e.g. a legacy
        # numeric id) and must not be folded into "unset" by a truthiness
        # check that only Python's "" happens to share with it -- unlike
        # PHP's empty(), Python's `if "0":` is already True, so this pins
        # that the guard is a plain truthiness check and nothing stricter.
        srv = MockServer(
            make_handler(
                200,
                {"items": [], "next_cursor": ""},
                assert_method="GET",
                assert_path="/api/v1/sdk/enrolments",
                assert_query={
                    "limit": "25",
                    "sort": "created_at",
                    "order": "desc",
                    "user_identifier": "0",
                },
            )
        )
        client = Client("rka_test", base_url=srv.url)
        client.list_enrolments(user_identifier="0")
        srv.stop()


class TestGetEnrolment:
    def test_get_enrolment_returns_none_when_not_linked(self, client_for):
        # Not an exception: "not linked" is the normal answer at login.
        client = client_for({"items": [], "next_cursor": ""})
        assert client.get_enrolment("ada@example.com") is None

    def test_get_enrolment_returns_the_single_match(self, client_for):
        client = client_for(
            {
                "items": [
                    {
                        "id": "en_1",
                        "user_identifier": "ada@example.com",
                        "created_at": "2026-09-15T09:00:00Z",
                        "last_auth_at": None,
                        "last_auth_outcome": None,
                        "push_ready": True,
                    }
                ],
                "next_cursor": "",
            }
        )
        enrolment = client.get_enrolment("ada@example.com")
        assert enrolment["id"] == "en_1"
        assert enrolment["push_ready"] is True


class TestGetPairingCodeStatus:
    def test_reads_the_code(self):
        srv = MockServer(
            make_handler(
                200,
                {"status": "redeemed", "enrolment_id": "en_1"},
                assert_method="GET",
                assert_path="/api/v1/sdk/pairing-codes/af17-b500",
            )
        )
        client = Client("rka_test", base_url=srv.url)
        status = client.get_pairing_code_status("af17-b500")
        assert status["status"] == "redeemed"
        srv.stop()

    def test_a_code_that_never_existed_and_one_from_another_app_both_read_expired(self):
        # Distinguishing the two would make this endpoint a probing oracle,
        # so both must read back exactly "expired" with nothing more.
        srv = MockServer(make_handler(200, {"status": "expired"}))
        client = Client("rka_test", base_url=srv.url)
        assert client.get_pairing_code_status("ghost-code")["status"] == "expired"
        srv.stop()


class TestWaitForLink:
    def test_polls_until_redeemed_then_returns_the_enrolment(self):
        url, stop = _serve(
            [
                '{"status":"pending"}',
                '{"status":"redeemed","enrolment_id":"en_1"}',
                json.dumps(
                    {
                        "items": [
                            {
                                "id": "en_1",
                                "user_identifier": "ada@example.com",
                                "created_at": "2026-09-15T09:00:00Z",
                                "last_auth_at": None,
                                "last_auth_outcome": None,
                                "push_ready": False,
                            }
                        ],
                        "next_cursor": "",
                    }
                ),
            ]
        )
        try:
            client = Client("rka_test", base_url=url)
            enrolment = client.wait_for_link(
                "af17-b500", user_identifier="ada@example.com", interval=0.001
            )
            assert enrolment["id"] == "en_1"
        finally:
            stop()

    def test_raises_on_expiry(self, client_for):
        client = client_for({"status": "expired"})
        with pytest.raises(U2AuthError) as excinfo:
            client.wait_for_link("af17-b500", user_identifier="ada@example.com", interval=0.001)
        assert excinfo.value.code == "PAIRING_CODE_EXPIRED"

    def test_times_out(self, client_for):
        client = client_for({"status": "pending"})
        with pytest.raises(U2AuthError) as excinfo:
            client.wait_for_link(
                "af17-b500", user_identifier="ada@example.com", interval=0.001, timeout=0.003
            )
        assert excinfo.value.code == "LINK_TIMEOUT"

    def test_raises_enrolment_not_found_when_redeemed_but_no_enrolment(self):
        # Redemption and the enrolment lookup are two separate backend calls
        # and can disagree.
        url, stop = _serve(
            [
                '{"status":"redeemed","enrolment_id":"en_1"}',
                '{"items":[],"next_cursor":""}',
            ]
        )
        try:
            client = Client("rka_test", base_url=url)
            with pytest.raises(U2AuthError) as excinfo:
                client.wait_for_link(
                    "af17-b500", user_identifier="ada@example.com", interval=0.001
                )
            assert excinfo.value.code == "ENROLMENT_NOT_FOUND"
        finally:
            stop()

    def test_requires_user_identifier(self, client_for):
        # PF6: unlike TypeScript, a Python type hint is not a runtime check.
        # An empty identifier must be rejected explicitly -- otherwise it
        # falls straight through the truthy filter in list_enrolments,
        # silently omits itself from the query, and wait_for_link can return
        # an unrelated enrolment once the code is redeemed.
        client = client_for({"status": "pending"})
        with pytest.raises(U2AuthError) as excinfo:
            client.wait_for_link("af17-b500", user_identifier="", interval=0.001, timeout=0.003)
        assert excinfo.value.code == "MISSING_USER_IDENTIFIER"


class TestDeleteEnrolment:
    def test_sends_delete_with_encoded_identifier(self):
        # "+" must survive as %2B rather than decoding to a space.
        srv = MockServer(
            make_handler(
                204,
                None,
                assert_method="DELETE",
                assert_path="/api/v1/sdk/enrolments",
                assert_query={"user_identifier": "alice+tag@acme.com"},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        assert client.delete_enrolment("alice+tag@acme.com") is None
        srv.stop()

    def test_not_found_raises(self):
        srv = MockServer(
            make_handler(
                404,
                {"error": {"code": "ENROLMENT_NOT_FOUND", "message": "no enrolment"}},
            )
        )
        client = Client("rka_test", base_url=srv.url)
        with pytest.raises(U2AuthError) as exc:
            client.delete_enrolment("ghost@acme.com")
        assert exc.value.code == "ENROLMENT_NOT_FOUND"
        assert exc.value.status_code == 404
        srv.stop()
