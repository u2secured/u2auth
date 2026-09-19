"""U2Auth API client — sync, stdlib only."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional


_DEFAULT_BASE_URL = "https://app.u2secured.io"


class U2AuthError(Exception):
    """Raised when the U2Auth API returns a 4xx/5xx error."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(f"U2Auth API error {status_code} {code}: {message}")
        self.status_code = status_code
        self.code = code


class Client:
    """Synchronous U2Auth API client."""

    def __init__(self, api_key: str, *, base_url: str = _DEFAULT_BASE_URL) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")

    def verify_totp(self, secret: str, code: str) -> Dict[str, Any]:
        """Verify a TOTP code. Returns {'valid': bool}."""
        return self._post("/api/v1/sdk/totp/verify", {"secret": secret, "code": code})

    def request_push(
        self,
        user_identifier: str,
        context: str,
        *,
        webhook_url: Optional[str] = None,
        ttl: Optional[int] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a push approval request. Returns {approval_id, status, expires_at}.

        Pass `idempotency_key` to make a repeated call return the ORIGINAL
        approval instead of sending the user a second notification. The key
        must be stable across the retry, so the SDK cannot invent one for
        you: derive it from whatever identifies the attempt in your system —
        a nonce rendered into the login form works well, because a
        double-click and a back-then-resubmit both carry the same one while
        a fresh page load mints a new one.

        This is not Stripe-style idempotency: there is no fixed replay
        window. The server frees the key once the approval is approved,
        denied or expired, so a genuine retry after that mints a new
        request rather than replaying the old one.

        A key held by a live approval for a DIFFERENT request raises
        U2AuthError with code 'IDEMPOTENCY_KEY_REUSED'. A key longer than
        255 characters raises U2AuthError with code
        'INVALID_IDEMPOTENCY_KEY'.
        """
        body: Dict[str, Any] = {
            "user_identifier": user_identifier,
            "context": context,
        }
        if webhook_url is not None:
            body["webhook_url"] = webhook_url
        if ttl is not None:
            body["ttl"] = ttl
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._post("/api/v1/sdk/push/request", body, headers)

    def get_push_status(self, approval_id: str) -> Dict[str, Any]:
        """Get the status of a push approval request. Returns {approval_id, status}."""
        return self._get(f"/api/v1/sdk/push/{approval_id}/status")

    def wait_for_approval(
        self, approval_id: str, timeout: float = 120, interval: float = 2
    ) -> Dict[str, Any]:
        """Poll get_push_status until the approval is no longer pending or timeout elapses."""
        deadline = time.monotonic() + timeout
        while True:
            status = self.get_push_status(approval_id)
            if status.get("status") != "pending":
                return status
            if time.monotonic() >= deadline:
                raise U2AuthError(0, "WAIT_TIMEOUT", "timed out waiting for approval")
            time.sleep(interval)

    def create_pairing_code(self, user_identifier: str) -> Dict[str, Any]:
        """Mint a pairing code binding user_identifier — your own opaque id for
        the user — to whichever account redeems it in the U2 Secured app. Pass
        the same string to request_push afterwards.

        Returns {'code', 'expires_at'}.
        """
        return self._post(
            "/api/v1/sdk/pairing-codes", {"user_identifier": user_identifier}
        )

    def delete_enrolment(self, user_identifier: str) -> None:
        """Remove the link between this app and user_identifier.

        Raises U2AuthError with code 'ENROLMENT_NOT_FOUND' if there was none.
        """
        query = urllib.parse.urlencode({"user_identifier": user_identifier})
        self._delete(f"/api/v1/sdk/enrolments?{query}")

    def list_enrolments(
        self,
        *,
        limit: int = 25,
        cursor: str = "",
        sort: str = "created_at",
        order: str = "desc",
        user_identifier: str = "",
    ) -> Dict[str, Any]:
        """List the enrolments for this app. The app is resolved from the
        API key — there is no app_id parameter. limit <= 0 is treated as
        unset and omitted from the query, same as an empty cursor or
        user_identifier. user_identifier is an arbitrary developer-chosen
        string, so the literal "0" is a legitimate value and is NOT treated
        as empty here — only "" is.

        cursor is opaque and bound to the sort/order that minted it — pass
        it back verbatim on the next call. Replaying it under a different
        sort/order raises U2AuthError with code 'INVALID_CURSOR'.

        Raises U2AuthError with code 'INVALID_LIMIT' if limit is outside
        1..100, or 'INVALID_SORT' for an unrecognised sort.

        Returns {'items': [...], 'next_cursor': '...'}.
        """
        params: Dict[str, Any] = {}
        if limit > 0:
            params["limit"] = limit
        if cursor:
            params["cursor"] = cursor
        params["sort"] = sort
        params["order"] = order
        if user_identifier:
            params["user_identifier"] = user_identifier
        query = urllib.parse.urlencode(params)
        return self._get(f"/api/v1/sdk/enrolments?{query}")

    def get_enrolment(self, user_identifier: str) -> Optional[Dict[str, Any]]:
        """Look up this app's enrolment for one user identifier.

        Returns None when the user is not linked. Deliberately not an
        exception: at login "not linked" is the normal answer, and a
        try/except on the common path is how integrations end up swallowing
        real errors too.
        """
        page = self.list_enrolments(user_identifier=user_identifier, limit=1)
        items = page.get("items") or []
        return items[0] if items else None

    def get_pairing_code_status(self, code: str) -> Dict[str, Any]:
        """Read whether a pairing code is pending, redeemed or gone.

        A code that never existed and one belonging to another app both
        report "expired" — distinguishing them would make this a probing
        oracle.
        """
        return self._get("/api/v1/sdk/pairing-codes/" + urllib.parse.quote(code, safe=""))

    def wait_for_link(
        self,
        code: str,
        *,
        user_identifier: str,
        interval: float = 2.0,
        timeout: float = 120.0,
    ) -> Dict[str, Any]:
        """Poll a pairing code until it is redeemed, then return the enrolment.

        The link half of link-then-push, mirroring wait_for_approval.

        Blocks. Call it from a worker, never from a request handler.

        Raises U2AuthError with code MISSING_USER_IDENTIFIER if
        user_identifier is empty — a type hint is not a runtime check in
        Python, so an empty string would otherwise fall straight through
        list_enrolments's truthy filter, drop itself from the query, and
        risk returning an unrelated enrolment on redemption instead of
        failing loudly. Also raises PAIRING_CODE_EXPIRED if the code lapses
        first, or LINK_TIMEOUT once the deadline passes.
        """
        if not user_identifier:
            raise U2AuthError(
                0, "MISSING_USER_IDENTIFIER", "wait_for_link requires user_identifier"
            )
        deadline = time.monotonic() + timeout
        while True:
            status = self.get_pairing_code_status(code)
            if status.get("status") == "redeemed":
                enrolment = self.get_enrolment(user_identifier)
                if enrolment is None:
                    raise U2AuthError(
                        0,
                        "ENROLMENT_NOT_FOUND",
                        "pairing code was redeemed but no enrolment was found for this identifier",
                    )
                return enrolment
            if status.get("status") == "expired":
                raise U2AuthError(
                    0, "PAIRING_CODE_EXPIRED", "pairing code expired before it was redeemed"
                )
            if time.monotonic() >= deadline:
                raise U2AuthError(
                    0, "LINK_TIMEOUT", "timed out waiting for the pairing code to be redeemed"
                )
            time.sleep(interval)

    def list_enrolment_events(
        self, enrolment_id: str, *, limit: int = 25, cursor: str = ""
    ) -> Dict[str, Any]:
        """List the authentication events recorded for one enrolment.
        limit <= 0 is treated as unset and omitted from the query, same as
        an empty cursor.

        cursor is opaque; pass it back verbatim on the next call to page.

        Raises U2AuthError with code 'ENROLMENT_NOT_FOUND' if there is no
        such enrolment, 'INVALID_LIMIT' if limit is outside 1..100, or
        'INVALID_CURSOR' if cursor is malformed or was minted for a
        different enrolment.

        Returns {'items': [...], 'next_cursor': '...'}.
        """
        params: Dict[str, Any] = {}
        if limit > 0:
            params["limit"] = limit
        if cursor:
            params["cursor"] = cursor
        query = urllib.parse.urlencode(params)
        enrolment_path = urllib.parse.quote(enrolment_id, safe="")
        path = f"/api/v1/sdk/enrolments/{enrolment_path}/events"
        return self._get(f"{path}?{query}" if query else path)

    def _post(
        self, path: str, body: Dict[str, Any], headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        data = json.dumps(body).encode()
        merged = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        if headers:
            merged.update(headers)
        req = urllib.request.Request(
            self._base_url + path,
            data=data,
            headers=merged,
            method="POST",
        )
        return self._send(req)

    def _get(self, path: str) -> Dict[str, Any]:
        req = urllib.request.Request(
            self._base_url + path,
            headers={"Authorization": f"Bearer {self._api_key}"},
            method="GET",
        )
        return self._send(req)

    def _delete(self, path: str) -> None:
        """DELETE with no response body. Separate from _send, which always
        json-decodes — a 204 carries an empty body."""
        req = urllib.request.Request(
            self._base_url + path,
            headers={"Authorization": f"Bearer {self._api_key}"},
            method="DELETE",
        )
        try:
            with urllib.request.urlopen(req):
                return None
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                payload = json.loads(body)
                err = payload.get("error", {})
                code = err.get("code", "UNKNOWN")
                message = err.get("message", "unknown error")
            except (json.JSONDecodeError, AttributeError):
                code, message = "UNKNOWN", body.decode(errors="replace")
            raise U2AuthError(exc.code, code, message) from exc

    def _send(self, req: urllib.request.Request) -> Dict[str, Any]:
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                payload = json.loads(body)
                err = payload.get("error", {})
                code = err.get("code", "UNKNOWN")
                message = err.get("message", "unknown error")
            except (json.JSONDecodeError, AttributeError):
                code, message = "UNKNOWN", body.decode(errors="replace")
            raise U2AuthError(exc.code, code, message) from exc
