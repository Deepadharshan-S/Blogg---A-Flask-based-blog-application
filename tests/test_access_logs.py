"""Access logs: the per-request IAM trail, gated viewing/export and retention.

Covers the sibling features of the audit trail: recording who reached what
(from where, with what result), who is allowed to read either trail, CSV/JSON
export of the audit trail, and retention pruning of both tables.
"""

from datetime import timedelta

from app import db
from app.models import AccessLog, AuditEvent, Role, utc_now
from app.security import Event, prune_expired_logs, sanitize_path
from tests.iam_base import IAMTestCase


class AccessLogTestCase(IAMTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user(
            email="root@example.com", username="root", role=self.admin_role()
        )
        self.user = self.make_user()

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def test_anonymous_request_is_recorded_without_identity(self):
        self.client.get("/")
        row = (
            AccessLog.query.filter_by(path="/", method="GET")
            .order_by(AccessLog.timestamp.desc())
            .first()
        )
        self.assertIsNotNone(row)
        self.assertIsNone(row.user_id)
        self.assertIsNone(row.user_label)
        self.assertEqual(row.status_code, 200)
        self.assertEqual(row.ip, "127.0.0.1")
        self.assertFalse(row.is_api)
        self.assertIsInstance(row.duration_ms, int)
        self.assertGreaterEqual(row.duration_ms, 0)
        self.assertIsNotNone(row.endpoint)

    def test_authenticated_requests_carry_the_session_identity(self):
        self.login()
        row = AccessLog.query.filter_by(path="/").order_by(AccessLog.timestamp.desc()).first()
        self.assertIsNotNone(row)
        self.assertEqual(row.user_id, self.user.id)
        self.assertEqual(row.user_label, self.user.email)
        self.assertEqual(row.status_code, 200)

    def test_static_assets_are_excluded_but_other_404s_are_logged(self):
        self.client.get("/static/css/does-not-exist.css")
        self.assertEqual(AccessLog.query.filter(AccessLog.path.like("/static%")).count(), 0)

        self.client.get("/no/such/page")
        not_found = (
            AccessLog.query.filter_by(path="/no/such/page")
            .order_by(AccessLog.timestamp.desc())
            .first()
        )
        self.assertIsNotNone(not_found)
        self.assertEqual(not_found.status_code, 404)

    def test_one_time_tokens_are_redacted_from_recorded_paths(self):
        self.client.get("/auth/reset/s3cret-reset-token-value")
        paths = [r.path for r in AccessLog.query.all()]
        self.assertIn("/auth/reset/***", paths)
        self.assertFalse(any("s3cret" in p for p in paths))

        self.client.get("/auth/confirm/s3cret-confirm-token-value")
        paths = [r.path for r in AccessLog.query.all()]
        self.assertIn("/auth/confirm/***", paths)
        self.assertFalse(any("s3cret" in p for p in paths))

    def test_api_requests_are_flagged_and_use_the_token_identity(self):
        # Browser session belongs to the regular user...
        self.login()
        # ...but the admin's API token must win for API requests.
        admin_token = self.issue_token(
            email=self.admin.email, password="Password123!", scopes=["admin"]
        )["token"]
        response = self.client.get(
            "/api/v1/admin/access-logs", headers=self.api_headers(admin_token)
        )
        self.assertEqual(response.status_code, 200)

        row = (
            AccessLog.query.filter_by(path="/api/v1/admin/access-logs")
            .order_by(AccessLog.timestamp.desc())
            .first()
        )
        self.assertIsNotNone(row)
        self.assertTrue(row.is_api)
        self.assertEqual(row.user_label, self.admin.email)
        self.assertEqual(row.user_id, self.admin.id)

        # g.current_user lingers in this test's shared app context; a later
        # web request must still resolve to the session identity, not it.
        self.client.get("/")
        row = AccessLog.query.filter_by(path="/").order_by(AccessLog.timestamp.desc()).first()
        self.assertEqual(row.user_label, self.user.email)

    def test_access_logging_can_be_disabled_via_config(self):
        before = AccessLog.query.count()
        self.app.config["BLOGG_ACCESS_LOG_ENABLED"] = False
        self.client.get("/")
        self.assertEqual(AccessLog.query.count(), before)

        self.app.config["BLOGG_ACCESS_LOG_ENABLED"] = True
        self.client.get("/")
        self.assertEqual(AccessLog.query.count(), before + 1)

    def test_sanitize_path_helper(self):
        self.assertEqual(sanitize_path(None), "/")
        self.assertEqual(sanitize_path("/posts/1"), "/posts/1")
        self.assertEqual(sanitize_path("/auth/confirm/abc.def.ghi"), "/auth/confirm/***")
        self.assertEqual(sanitize_path("/auth/change_email/t0ken"), "/auth/change_email/***")
        self.assertEqual(len(sanitize_path("/" + "x" * 500)), 256)

    # ------------------------------------------------------------------
    # Console gating & filters
    # ------------------------------------------------------------------

    def test_access_log_web_view_requires_view_audit(self):
        self.login()
        self.assertEqual(self.client.get("/admin/access-logs").status_code, 403)
        self.logout()

        moderator = self.make_user(
            email="mod@example.com",
            username="mod",
            role=Role.query.filter_by(name="Moderator").first(),
        )
        self.login(email=moderator.email)
        self.assertEqual(self.client.get("/admin/access-logs").status_code, 403)
        self.logout()

        self.login(email=self.admin.email)
        response = self.client.get("/admin/access-logs")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Access Log", response.get_data(as_text=True))

        # Filters that match nothing render the empty state.
        for qs in ("?method=DELETE", "?status=5xx", "?q=no-such-path-anywhere"):
            response = self.client.get(f"/admin/access-logs{qs}")
            self.assertEqual(response.status_code, 200)
            self.assertIn("No access records match this filter.", response.get_data(as_text=True))

        # The dashboard surfaces the access-trail size next to the audit count.
        response = self.client.get("/admin/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("access record(s)", response.get_data(as_text=True))

    def test_viewing_either_log_is_itself_audited(self):
        self.login(email=self.admin.email)

        self.client.get("/admin/audit")
        self.assertIsNotNone(
            AuditEvent.query.filter_by(event=Event.AUDIT_VIEWED, actor_id=self.admin.id).first()
        )

        self.client.get("/admin/access-logs")
        web_viewed = AuditEvent.query.filter_by(
            event=Event.ACCESS_LOG_VIEWED, actor_id=self.admin.id
        ).count()
        self.assertEqual(web_viewed, 1)

        admin_token = self.issue_token(
            email=self.admin.email, password="Password123!", scopes=["admin"]
        )["token"]
        response = self.client.get(
            "/api/v1/admin/access-logs", headers=self.api_headers(admin_token)
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AuditEvent.query.filter_by(event=Event.ACCESS_LOG_VIEWED).count(), 2)
        # ...and reading the audit trail over the API is audited as well.
        response = self.client.get("/api/v1/admin/audit", headers=self.api_headers(admin_token))
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(AuditEvent.query.filter_by(event=Event.AUDIT_VIEWED).first())

    # ------------------------------------------------------------------
    # REST API
    # ------------------------------------------------------------------

    def test_access_log_api_requires_admin_scope_and_permission(self):
        # Missing scope on an admin-owned token.
        no_scope = self.issue_token(email=self.admin.email, password="Password123!")["token"]
        response = self.client.get("/api/v1/admin/access-logs", headers=self.api_headers(no_scope))
        self.assertEqual(response.status_code, 403)
        self.assertIn("admin", response.get_json()["message"])

        # Admin scope but non-privileged account: permission check still blocks.
        user_token = self.issue_token(scopes=["admin"])["token"]
        response = self.client.get(
            "/api/v1/admin/access-logs", headers=self.api_headers(user_token)
        )
        self.assertEqual(response.status_code, 403)

        # Full admin token: allowed.
        admin_token = self.issue_token(
            email=self.admin.email,
            password="Password123!",
            scopes=["admin", "tokens:manage"],
        )["token"]
        response = self.client.get(
            "/api/v1/admin/access-logs", headers=self.api_headers(admin_token)
        )
        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIn("access_logs", body)
        self.assertIn("total", body)
        self.assertGreater(body["total"], 0)
        self.assertTrue(all("path" in row for row in body["access_logs"]))

        # Filtering by method and status class.
        response = self.client.get(
            "/api/v1/admin/access-logs?method=GET",
            headers=self.api_headers(admin_token),
        )
        self.assertEqual(response.status_code, 200)
        rows = response.get_json()["access_logs"]
        self.assertTrue(rows)
        self.assertTrue(all(row["method"] == "GET" for row in rows))

        response = self.client.get(
            "/api/v1/admin/access-logs?status=5xx",
            headers=self.api_headers(admin_token),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["access_logs"], [])

    # ------------------------------------------------------------------
    # Audit export
    # ------------------------------------------------------------------

    def test_audit_export_is_gated_and_audited(self):
        self.login()
        self.assertEqual(self.client.get("/admin/audit/export?format=csv").status_code, 403)
        self.logout()

        self.login(email=self.admin.email)
        response = self.client.get("/admin/audit/export?format=csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("audit-log.csv", response.headers.get("Content-Disposition", ""))
        header = response.get_data(as_text=True).splitlines()[0]
        self.assertEqual(
            header,
            "id,timestamp,event,actor,target_type,target_id,target,success,ip,user_agent,detail",
        )

        response = self.client.get("/admin/audit/export?format=json")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("events", data)
        self.assertIsInstance(data["events"], list)
        self.assertGreaterEqual(data["count"], 1)

        self.assertEqual(self.client.get("/admin/audit/export?format=xml").status_code, 400)

        exported = AuditEvent.query.filter_by(
            event=Event.AUDIT_EXPORTED, actor_id=self.admin.id
        ).count()
        self.assertEqual(exported, 2)

    # ------------------------------------------------------------------
    # Retention pruning
    # ------------------------------------------------------------------

    def test_retention_disabled_by_default_and_pruning_is_audited(self):
        old = AccessLog(method="GET", path="/old", status_code=200)
        old.timestamp = utc_now() - timedelta(days=40)
        db.session.add(old)
        db.session.commit()

        # Default retention (0 days) keeps everything.
        counts = prune_expired_logs()
        self.assertEqual(counts, {"audit_events": 0, "access_logs": 0})
        self.assertEqual(AccessLog.query.count(), 1)
        self.assertIsNone(AuditEvent.query.filter_by(event=Event.LOGS_PRUNED).first())

        # With retention enabled, only expired rows go - and the prune is audited.
        self.app.config["BLOGG_ACCESS_LOG_RETENTION_DAYS"] = 30
        self.app.config["BLOGG_AUDIT_RETENTION_DAYS"] = 30
        old_event = AuditEvent(event="test.old", success=True)
        old_event.timestamp = utc_now() - timedelta(days=40)
        db.session.add(old_event)
        db.session.commit()

        counts = prune_expired_logs()
        self.assertEqual(counts, {"audit_events": 1, "access_logs": 1})
        self.assertEqual(AccessLog.query.count(), 0)
        self.assertEqual(AuditEvent.query.filter_by(event="test.old").count(), 0)
        pruned = AuditEvent.query.filter_by(event=Event.LOGS_PRUNED).first()
        self.assertIsNotNone(pruned)
        self.assertIn("access_logs", pruned.detail)

    def test_prune_logs_cli_command(self):
        self.app.config["BLOGG_ACCESS_LOG_RETENTION_DAYS"] = 1
        old = AccessLog(method="GET", path="/old", status_code=200)
        old.timestamp = utc_now() - timedelta(days=5)
        db.session.add(old)
        db.session.commit()

        runner = self.app.test_cli_runner()
        result = runner.invoke(args=["prune-logs"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("Pruned 0 audit event(s) and 1 access record(s).", result.output)
        self.assertEqual(AccessLog.query.count(), 0)
