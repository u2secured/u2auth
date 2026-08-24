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
    ) -> Dict[str, Any]:
        """Create a push approval request. Returns {approval_id, status, expires_at}."""
        body: Dict[str, Any] = {
            "user_identifier": user_identifier,
            "context": context,
        }
        if webhook_url is not None:
            body["webhook_url"] = webhook_url
        if ttl is not None:
            body["ttl"] = ttl
        return self._post("/api/v1/sdk/push/request", body)

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
    ) -> Dict[str, Any]:
        """List the enrolments for this app. The app is resolved from the
        API key — there is no app_id parameter. limit <= 0 is treated as
        unset and omitted from the query, same as an empty cursor.

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
        query = urllib.parse.urlencode(params)
        return self._get(f"/api/v1/sdk/enrolments?{query}")

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

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            self._base_url + path,
            data=data,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
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
