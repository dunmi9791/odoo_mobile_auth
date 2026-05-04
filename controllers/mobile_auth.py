import hashlib
import json
import logging
import secrets
import urllib.error
import urllib.request

from odoo import fields, http
from odoo.exceptions import AccessDenied
from odoo.http import request


_logger = logging.getLogger(__name__)
TOKEN_TTL_SECONDS = 60 * 60 * 12


def _read_json():
    raw = request.httprequest.get_data(as_text=True) or "{}"
    return json.loads(raw)


def _json_response(payload, status=200):
    return request.make_response(
        json.dumps(payload, default=_json_default),
        headers=[
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Headers", "Content-Type, Authorization"),
            ("Access-Control-Allow-Methods", "POST, OPTIONS"),
        ],
        status=status,
    )


def _json_default(value):
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _rpc_id(payload=None):
    return (payload or {}).get("id", 1)


def _rpc_success(data, payload=None):
    return {
        "jsonrpc": "2.0",
        "id": _rpc_id(payload),
        "result": data,
    }


def _rpc_error(message, code=100, status=200, payload=None):
    return _json_response({
        "jsonrpc": "2.0",
        "id": _rpc_id(payload),
        "error": {
            "code": code,
            "message": message,
        },
    }, status=status)


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _authenticate_session(db, login, password):
    credential = {
        "login": login,
        "password": password,
        "type": "password",
    }

    auth_result = None

    try:
        auth_result = request.session.authenticate(db, credential)
    except TypeError:
        auth_result = request.session.authenticate(db, login, password)

    if isinstance(auth_result, dict):
        uid = auth_result.get("uid")
        session_id = auth_result.get("session_id") or auth_result.get("sid")
    else:
        uid = auth_result
        session_id = None

    return uid or request.session.uid, session_id or request.session.sid


def _save_current_session():
    if hasattr(request.session, "save"):
        request.session.save()
        return

    session_store = getattr(getattr(http, "root", None), "session_store", None)
    if session_store:
        session_store.save(request.session)


def _bearer_token():
    auth_header = request.httprequest.headers.get("Authorization", "")
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        return None
    return auth_header[len(prefix):].strip()


def _mobile_token_record():
    token = _bearer_token()
    if not token:
        return None

    token_record = request.env["workshop.mobile.token"].sudo().search([
        ("token_hash", "=", _hash_token(token)),
        ("active", "=", True),
        ("expires_at", ">", fields.Datetime.now()),
    ], limit=1)

    if not token_record:
        return None

    token_record.write({"last_used_at": fields.Datetime.now()})
    return token_record


def _forward_existing_workshop_route(token_record, endpoint, payload):
    upstream_payload = json.dumps(payload).encode("utf-8")
    base_url = request.env["ir.config_parameter"].sudo().get_param("web.base.url")
    url = "%s/api/workshop/%s" % (base_url.rstrip("/"), endpoint)
    cookie = "session_id=%s; db=%s" % (token_record.session_id, request.env.cr.dbname)

    upstream_request = urllib.request.Request(
        url,
        data=upstream_payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Cookie": cookie,
            "X-Openerp-Session-Id": token_record.session_id,
            "User-Agent": "WrenchLaneGarageFlow-OdooMobileAuth/1.0",
        },
    )

    _logger.info(
        "Forwarding mobile workshop request endpoint=%s user=%s session_id_prefix=%s",
        endpoint,
        token_record.user_id.id,
        (token_record.session_id or "")[:8],
    )

    try:
        with urllib.request.urlopen(upstream_request, timeout=60) as upstream:
            status = upstream.status
            body = upstream.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read().decode("utf-8")

    try:
        data = json.loads(body) if body else {}
    except json.JSONDecodeError:
        data = {
            "jsonrpc": "2.0",
            "id": _rpc_id(payload),
            "error": {
                "code": status,
                "message": body or "Upstream workshop API returned a non-JSON response",
            },
        }

    return _json_response(data, status=status)


class WorkshopMobileAuthController(http.Controller):
    @http.route("/mobile/authenticate", type="http", auth="none", methods=["POST", "OPTIONS"], csrf=False)
    def mobile_authenticate(self, **kwargs):
        if request.httprequest.method == "OPTIONS":
            return _json_response({}, status=204)

        payload = _read_json()
        params = payload.get("params") or payload
        db = params.get("db") or request.session.db or request.db
        login = params.get("login")
        password = params.get("password")

        if not db or not login or not password:
            return _rpc_error("db, login and password are required", code=400, status=400, payload=payload)

        try:
            uid, session_id = _authenticate_session(db, login, password)
        except AccessDenied:
            return _rpc_error("Invalid credentials", code=401, status=401, payload=payload)
        except Exception:
            _logger.exception("Mobile authentication failed")
            return _rpc_error("Mobile authentication failed on the Odoo server", code=500, status=500, payload=payload)

        if not uid:
            return _rpc_error("Invalid credentials", code=401, status=401, payload=payload)

        _save_current_session()

        user = request.env["res.users"].sudo().browse(uid)
        token = secrets.token_urlsafe(48)
        expires_at = fields.Datetime.add(fields.Datetime.now(), seconds=TOKEN_TTL_SECONDS)

        request.env["workshop.mobile.token"].sudo().create({
            "token_hash": _hash_token(token),
            "user_id": uid,
            "session_id": session_id,
            "expires_at": expires_at,
        })

        _logger.info(
            "Created mobile token for user=%s session_id_prefix=%s request_sid_prefix=%s",
            uid,
            (session_id or "")[:8],
            (request.session.sid or "")[:8],
        )

        return _json_response(_rpc_success({
            "uid": uid,
            "name": user.name,
            "username": user.login,
            "mobile_token": token,
            "mobile_expires_at": expires_at,
            "mobile_expires_in": TOKEN_TTL_SECONDS,
        }, payload=payload))

    @http.route("/mobile/logout", type="http", auth="none", methods=["POST", "OPTIONS"], csrf=False)
    def mobile_logout(self, **kwargs):
        if request.httprequest.method == "OPTIONS":
            return _json_response({}, status=204)

        token = _bearer_token()
        if token:
            request.env["workshop.mobile.token"].sudo().search([
                ("token_hash", "=", _hash_token(token)),
            ]).write({"active": False})
        return _json_response({"success": True})

    @http.route("/mobile/api/workshop/<path:endpoint>", type="http", auth="none", methods=["POST", "OPTIONS"], csrf=False)
    def mobile_workshop_api(self, endpoint, **kwargs):
        if request.httprequest.method == "OPTIONS":
            return _json_response({}, status=204)

        payload = _read_json()
        token_record = _mobile_token_record()
        if not token_record:
            return _rpc_error("Mobile session expired", code=401, status=401, payload=payload)

        return _forward_existing_workshop_route(token_record, endpoint, payload)
