from odoo import api, fields, models


class WorkshopMobileToken(models.Model):
    _name = "workshop.mobile.token"
    _description = "Workshop Mobile API Token"
    _rec_name = "user_id"

    token_hash = fields.Char(required=True, index=True, copy=False)
    user_id = fields.Many2one("res.users", required=True, ondelete="cascade", index=True)
    session_id = fields.Char(required=True, copy=False)
    expires_at = fields.Datetime(required=True, index=True)
    active = fields.Boolean(default=True, index=True)
    last_used_at = fields.Datetime()

    @api.autovacuum
    def _gc_expired_tokens(self):
        self.search([
            "|",
            ("active", "=", False),
            ("expires_at", "<", fields.Datetime.now()),
        ]).unlink()
