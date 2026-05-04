import hashlib
import json
import secrets
import urllib.error
import urllib.request

from odoo import fields, http
from odoo.http import request
from odoo.tools import date_utils


TOKEN_TTL_SECONDS = 60 * 60 * 12


def _json_response(payload, status=200):
    return request.make_json_response(payload, status=status)


def _rpc_success(data):
    return {
        "jsonrpc": "2.0",
        "id": request.jsonrequest.get("id") if request.jsonrequest else 1,
        "result": {
            "success": True,
            "data": data,
        },
    }


def _rpc_error(message, code=100, status=200):
    return _json_response({
        "jsonrpc": "2.0",
        "id": request.jsonrequest.get("id") if request.jsonrequest else 1,
        "error": {
            "code": code,
            "message": message,
        },
    }, status=status)


def _hash_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bearer_token():
    auth_header = request.httprequest.headers.get("Authorization", "")
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        return None
    return auth_header[len(prefix):].strip()


def _mobile_user():
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


def _forward_existing_workshop_route(token_record, endpoint):
    payload = json.dumps(request.jsonrequest or {}).encode("utf-8")
    base_url = request.env["ir.config_parameter"].sudo().get_param("web.base.url")
    url = "%s/api/workshop/%s" % (base_url.rstrip("/"), endpoint)

    upstream_request = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Cookie": "session_id=%s" % token_record.session_id,
            "User-Agent": "WrenchLaneGarageFlow-OdooMobileAuth/1.0",
        },
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
            "id": request.jsonrequest.get("id") if request.jsonrequest else 1,
            "error": {
                "code": status,
                "message": body or "Upstream workshop API returned a non-JSON response",
            },
        }

    return _json_response(data, status=status)


class WorkshopMobileAuthController(http.Controller):
    @http.route("/mobile/authenticate", type="json", auth="none", methods=["POST"], csrf=False)
    def mobile_authenticate(self, **kwargs):
        params = (request.jsonrequest or {}).get("params") or kwargs
        db = params.get("db") or request.session.db
        login = params.get("login")
        password = params.get("password")

        if not db or not login or not password:
            return _rpc_error("db, login and password are required", code=400, status=400)

        uid = request.session.authenticate(db, login, password)
        if not uid:
            return _rpc_error("Invalid credentials", code=401, status=401)

        user = request.env["res.users"].sudo().browse(uid)
        token = secrets.token_urlsafe(48)
        expires_at = fields.Datetime.add(fields.Datetime.now(), seconds=TOKEN_TTL_SECONDS)

        request.env["workshop.mobile.token"].sudo().create({
            "token_hash": _hash_token(token),
            "user_id": uid,
            "session_id": request.session.sid,
            "expires_at": expires_at,
        })

        return {
            "uid": uid,
            "name": user.name,
            "username": user.login,
            "mobile_token": token,
            "mobile_expires_at": date_utils.json_default(expires_at),
            "mobile_expires_in": TOKEN_TTL_SECONDS,
        }

    @http.route("/mobile/logout", type="json", auth="none", methods=["POST"], csrf=False)
    def mobile_logout(self, **kwargs):
        token = _bearer_token()
        if token:
            request.env["workshop.mobile.token"].sudo().search([
                ("token_hash", "=", _hash_token(token)),
            ]).write({"active": False})
        return {"success": True}

    @http.route("/mobile/api/workshop/<path:endpoint>", type="json", auth="none", methods=["POST"], csrf=False)
    def mobile_workshop_api(self, endpoint, **kwargs):
        token_record = _mobile_user()
        if not token_record:
            return _rpc_error("Mobile session expired", code=401, status=401)

        return _forward_existing_workshop_route(token_record, endpoint)
