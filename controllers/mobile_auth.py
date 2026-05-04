import hashlib
import json
import logging
import secrets

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
        "result": {
            "success": True,
            "data": data,
        },
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


def _normalize_workshop_payload(result, payload=None):
    if isinstance(result, dict) and "jsonrpc" in result:
        rpc_result = result.get("result")
        if isinstance(rpc_result, dict) and "success" in rpc_result:
            return result

        if "result" in result:
            return {
                **result,
                "result": {
                    "success": True,
                    "data": rpc_result,
                },
            }

        return result

    if isinstance(result, dict) and "success" in result and "data" in result:
        return {
            "jsonrpc": "2.0",
            "id": _rpc_id(payload),
            "result": result,
        }

    return _rpc_success(result, payload=payload)


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
    save = getattr(request.session, "save", None)
    if callable(save):
        save()
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


def _become_mobile_user(token_record):
    uid = token_record.user_id.id
    request.session.uid = uid
    request.session.login = token_record.user_id.login
    request.session.db = request.env.cr.dbname

    update_env = getattr(request, "update_env", None)
    if callable(update_env):
        update_env(user=uid)
    else:
        request.uid = uid


def _dispatch_existing_workshop_route(token_record, endpoint, payload):
    _become_mobile_user(token_record)

    path = "/api/workshop/%s" % endpoint
    routing = request.env["ir.http"]
    routing_map_method = getattr(routing, "_routing_map", None) or getattr(routing, "routing_map")
    routing_map = routing_map_method()
    adapter = routing_map.bind_to_environ(request.httprequest.environ)

    _logger.info(
        "Dispatching mobile workshop request endpoint=%s user=%s session_id_prefix=%s",
        endpoint,
        token_record.user_id.id,
        (token_record.session_id or "")[:8],
    )

    rule, arguments = adapter.match(path_info=path, method="POST", return_rule=True)
    result = rule.endpoint(**arguments)

    if hasattr(result, "status_code"):
        return result

    return _json_response(_normalize_workshop_payload(result, payload=payload))


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

        return _json_response({
            "jsonrpc": "2.0",
            "id": _rpc_id(payload),
            "result": {
                "uid": uid,
                "name": user.name,
                "username": user.login,
                "mobile_token": token,
                "mobile_expires_at": expires_at,
                "mobile_expires_in": TOKEN_TTL_SECONDS,
            },
        })

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

        return _dispatch_existing_workshop_route(token_record, endpoint, payload)
