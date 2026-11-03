"""BLOGG-SEC-014: Content Security Policy (CSP) hardening tests.

Verifies:
1. Per-request cryptographically secure CSP nonce generation.
2. Nonce is included in script-src and style-src CSP header directives.
3. Complete elimination of 'unsafe-inline' and avoidance of 'unsafe-eval'.
4. Unique nonces generated on each request.
5. Jinja template integration: inline script tags include matching nonce attributes.
6. Moment.js integration includes the nonce attribute.
7. Error pages and authenticated admin views retain strict CSP with nonces.
"""

import re

from flask import g

from tests.iam_base import IAMTestCase


class CSPHardeningTestCase(IAMTestCase):
    def test_csp_header_structure_and_no_unsafe_inline(self):
        """Verify CSP headers have nonce and completely lack 'unsafe-inline' or 'unsafe-eval'."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

        csp = response.headers.get("Content-Security-Policy", "")
        self.assertTrue(csp, "Content-Security-Policy header must be present")

        # Must not contain unsafe directives
        self.assertNotIn(
            "'unsafe-inline'",
            csp,
            "CSP must not contain 'unsafe-inline' in any directive",
        )
        self.assertNotIn(
            "'unsafe-eval'",
            csp,
            "CSP must not contain 'unsafe-eval'",
        )

        # Must contain nonces for scripts and styles
        self.assertRegex(
            csp,
            r"script-src[^;]*'nonce-[A-Za-z0-9_-]+'",
            "script-src must include a cryptographic nonce",
        )
        self.assertRegex(
            csp,
            r"style-src[^;]*'nonce-[A-Za-z0-9_-]+'",
            "style-src must include a cryptographic nonce",
        )

        # Verify script-src-attr directive allows jQuery feature-detection hash via unsafe-hashes
        self.assertIn("script-src-attr", csp)
        self.assertIn("'sha256-47mKTaNxEn1L3mSDAz9muidMqwW3Gxcw7CFAK/YnPdg='", csp)

    def test_no_inline_event_handlers_in_templates(self):
        """Verify rendered pages avoid inline onsubmit/onclick handlers in favor of data-confirm."""
        for path in ["/", "/auth/login", "/auth/register"]:
            res = self.client.get(path)
            self.assertEqual(res.status_code, 200)
            html = res.get_data(as_text=True)
            self.assertNotIn("onsubmit=", html, f"Path {path} must not contain inline onsubmit")

    def test_csp_disallows_http_origins(self):
        """SEC-ASSESS-001: Verify all external CDN origins strictly enforce HTTPS."""
        response = self.client.get("/")
        csp = response.headers.get("Content-Security-Policy", "")

        # Must not contain unencrypted HTTP schemes in script-src, style-src, or any directive
        self.assertNotIn("http://", csp, "CSP must not contain unencrypted http:// origins")
        self.assertIn("https://cdnjs.cloudflare.com", csp)
        self.assertIn("https://cdn.jsdelivr.net", csp)
        self.assertIn("https://fonts.googleapis.com", csp)

    def test_csp_nonce_is_unique_per_request(self):
        """Verify that every HTTP request generates a unique nonce."""
        res1 = self.client.get("/")
        res2 = self.client.get("/")

        csp1 = res1.headers.get("Content-Security-Policy", "")
        csp2 = res2.headers.get("Content-Security-Policy", "")

        match1 = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp1)
        match2 = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp2)

        self.assertIsNotNone(match1, "First request must have a CSP nonce")
        self.assertIsNotNone(match2, "Second request must have a CSP nonce")

        nonce1 = match1.group(1)
        nonce2 = match2.group(1)

        self.assertNotEqual(nonce1, nonce2, "Nonces must be distinct between requests")
        self.assertGreaterEqual(len(nonce1), 16, "Nonce must have adequate cryptographic length")

    def test_csp_nonce_injected_into_inline_scripts(self):
        """Verify rendered HTML includes the exact nonce in inline script tags."""
        response = self.client.get("/")
        html = response.get_data(as_text=True)
        csp = response.headers.get("Content-Security-Policy", "")

        match = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp)
        self.assertIsNotNone(match)
        expected_nonce = match.group(1)

        # Check all <script> tags: none should be bare <script> without nonce or src
        script_tags = re.findall(r"<script([^>]*)>", html, re.IGNORECASE)
        self.assertTrue(script_tags, "Page should contain script tags")

        for attrs in script_tags:
            # If it's an external script with src, that's allowed by domain whitelist,
            # but inline scripts without src MUST have the nonce.
            if "src=" not in attrs:
                self.assertIn(
                    f'nonce="{expected_nonce}"',
                    attrs,
                    f"Inline script tag missing matching nonce: <script{attrs}>",
                )

    def test_flask_moment_includes_csp_nonce(self):
        """Verify Flask-Moment inline initialization includes request nonce."""
        with self.app.test_request_context("/"):
            g.csp_nonce = "test-crypto-nonce-999"
            import flask_moment

            rendered_moment = flask_moment.moment.include_moment()
            self.assertIn(
                'nonce="test-crypto-nonce-999"',
                rendered_moment,
                "Moment.include_moment must include the active request CSP nonce",
            )

    def test_error_pages_retain_strict_csp_and_nonce(self):
        """Verify 404 error page has strict CSP without unsafe-inline and matching nonce."""
        response = self.client.get("/non-existent-endpoint-404")
        self.assertEqual(response.status_code, 404)

        csp = response.headers.get("Content-Security-Policy", "")
        self.assertNotIn("'unsafe-inline'", csp)
        self.assertIn("'nonce-", csp)

        html = response.get_data(as_text=True)
        match = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp)
        self.assertIsNotNone(match)
        nonce = match.group(1)
        self.assertIn(f'nonce="{nonce}"', html)

    def test_authenticated_and_admin_pages_csp(self):
        """Verify admin console and auth views emit nonced CSP without unsafe-inline."""
        admin = self.make_user(
            email="admin_csp@example.com",
            role=self.admin_role(),
        )
        self.login(email=admin.email)

        for path in ["/admin/", "/admin/users", "/auth/security"]:
            res = self.client.get(path)
            self.assertIn(res.status_code, (200, 302))
            csp = res.headers.get("Content-Security-Policy", "")
            self.assertNotIn("'unsafe-inline'", csp)
            self.assertIn("'nonce-", csp)

    def test_flask_pagedown_includes_csp_nonce_and_https_cdn(self):
        """Verify Flask-Pagedown scripts enforce HTTPS and include active CSP nonce."""
        with self.app.test_request_context("/"):
            g.csp_nonce = "test-pagedown-nonce-456"
            import flask_pagedown

            pd = flask_pagedown._pagedown()
            rendered = pd.include_pagedown()
            self.assertIn("https://cdnjs.cloudflare.com", rendered)
            self.assertNotIn("http://cdnjs.cloudflare.com", rendered)
            self.assertIn('nonce="test-pagedown-nonce-456"', rendered)

    def test_flask_pagedown_widget_includes_csp_nonce(self):
        """Verify Flask-Pagedown form widget injects active CSP nonce on inline preview script."""
        with self.app.test_request_context("/"):
            g.csp_nonce = "test-widget-nonce-789"
            from app.main.forms import PostForm

            form = PostForm()
            rendered = str(form.body())
            self.assertIn('<script type="text/javascript" nonce="test-widget-nonce-789">', rendered)

    def test_flask_moment_no_inline_styles(self):
        """Verify Flask-Moment rendering does not introduce inline style='display: none'."""
        with self.app.test_request_context("/"):
            import datetime

            import flask_moment

            m = flask_moment.moment(datetime.datetime.now(datetime.timezone.utc))
            rendered = m.fromNow()
            self.assertNotIn('style="display: none"', rendered)
            self.assertNotIn('style="display:none"', rendered)

    def test_gravatar_uses_https_url(self):
        """Verify User.gravatar always returns an HTTPS URL compliant with CSP."""
        user = self.make_user(email="avatar_test@example.com")
        with self.app.test_request_context("/"):
            url = user.gravatar(size=48)
            self.assertTrue(url.startswith("https://secure.gravatar.com/avatar/"))
            self.assertNotIn("http://", url)
