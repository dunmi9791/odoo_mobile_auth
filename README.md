# Workshop Mobile Auth Odoo Addon

Deploy this folder as an Odoo addon on the same Odoo server that hosts the existing workshop API.

## Install

1. Copy `server/odoo_mobile_auth` into one of your Odoo addons paths.
2. Restart Odoo.
3. Update the apps list.
4. Install **Workshop Mobile Auth**.

## Endpoints

### `POST /mobile/authenticate`

Body:

```json
{
  "jsonrpc": "2.0",
  "method": "call",
  "params": {
    "db": "riders18",
    "login": "user@example.com",
    "password": "password"
  },
  "id": 1
}
```

Returns the normal Odoo auth payload plus:

```json
{
  "mobile_token": "bearer-token",
  "mobile_expires_in": 43200
}
```

### `POST /mobile/api/workshop/<endpoint>`

Header:

```text
Authorization: Bearer <mobile_token>
```

The addon forwards the request to the existing `/api/workshop/<endpoint>` route with the stored Odoo session cookie. For example:

```text
/mobile/api/workshop/dashboard -> /api/workshop/dashboard
/mobile/api/workshop/jobcards -> /api/workshop/jobcards
```
# odoo_mobile_auth
