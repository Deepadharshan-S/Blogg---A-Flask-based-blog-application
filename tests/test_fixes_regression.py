"""Regression tests for the P0/P1 UI + functionality fixes.

Covers: privilege-escalation guards, active-only last-admin arithmetic,
form-input preservation on failed validation, LIKE escaping, themed error
pages (400/404/405/429), flash categories, anonymous navigation, self-follow
guards, moderation flash/audit, tombstoned-account guards and pagination.
"""

from app import db, limiter
from app.models import AuditEvent, Comment, Permission, Post, Role
from app.security import Event
from tests.iam_base import IAMTestCase


class PrivilegeEscalationTestCase(IAMTestCase):
    """A MANAGE_USERS operator must not be able to mint administrators."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_user(
            email="root@example.com", username="root", role=self.admin_role()
        )
        self.target = self.make_user(email="target@example.com", username="target")
        self.ops_role = Role(
            name="Ops", permissions=Permission.MANAGE_USERS | Permission.VIEW_AUDIT
        )
        db.session.add(self.ops_role)
        db.session.commit()
        self.ops = self.make_user(email="ops@example.com", username="ops", role=self.ops_role)

    def test_operator_cannot_grant_admin_via_console(self):
        admin_role = self.admin_role()
        self.login(email=self.ops.email)
        response = self.post_form(
            f"/admin/users/{self.target.id}",
            {"action": "role", "role_id": admin_role.id},
            page=f"/admin/users/{self.target.id}",
            follow_redirects=True,
        )
        self.assertIn(
            "Only administrators can grant the Administrator permission.",
            self.page_text(response),
        )
        db.session.refresh(self.target)
        self.assertEqual(self.target.role.name, "User")

    def test_admin_can_still_grant_admin_via_console(self):
        admin_role = self.admin_role()
        self.login(email=self.admin.email)
        response = self.post_form(
            f"/admin/users/{self.target.id}",
            {"action": "role", "role_id": admin_role.id},
            page=f"/admin/users/{self.target.id}",
            follow_redirects=True,
        )
        self.assertIn("is now Administrator.", self.page_text(response))
        db.session.refresh(self.target)
        self.assertEqual(self.target.role.name, "Administrator")

    def test_operator_cannot_grant_admin_via_api(self):
        token = self.issue_token(email=self.ops.email, password="Password123!", scopes=["admin"])[
            "token"
        ]
        response = self.client.patch(
            f"/api/v1/admin/users/{self.target.id}",
            headers=self.api_headers(token),
            json={"role": "Administrator"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn("Only administrators can grant", response.get_json()["message"])
        db.session.refresh(self.target)
        self.assertEqual(self.target.role.name, "User")


class LastAdminArithmeticTestCase(IAMTestCase):
    """Last-admin guards count *active* administrators only."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_user(
            email="root@example.com", username="root", role=self.admin_role()
        )
        self.disabled_admin = self.make_user(
            email="old@example.com", username="oldadmin", role=self.admin_role()
        )
        self.disabled_admin.active = False
        db.session.commit()
        self.ops_role = Role(
            name="Ops", permissions=Permission.MANAGE_USERS | Permission.VIEW_AUDIT
        )
        db.session.add(self.ops_role)
        db.session.commit()
        self.ops = self.make_user(email="ops@example.com", username="ops", role=self.ops_role)

    def test_disabled_admin_does_not_count_for_demotion(self):
        """Regression: with two admins (one disabled) the old arithmetic
        allowed demoting the only *active* admin, reaching zero."""
        self.login(email=self.ops.email)
        response = self.post_form(
            f"/admin/users/{self.admin.id}",
            {"action": "role", "role_id": Role.query.filter_by(name="User").first().id},
            page=f"/admin/users/{self.admin.id}",
            follow_redirects=True,
        )
        self.assertIn("Cannot demote the last administrator.", self.page_text(response))
        db.session.refresh(self.admin)
        self.assertEqual(self.admin.role.name, "Administrator")

    def test_disabled_admin_can_still_be_demoted(self):
        """Demoting a *disabled* admin cannot reduce the active count."""
        user_role = Role.query.filter_by(name="User").first()
        self.make_user(email="admin2@example.com", username="admin2", role=self.admin_role())
        self.login(email=self.admin.email)
        response = self.post_form(
            f"/admin/users/{self.disabled_admin.id}",
            {"action": "role", "role_id": user_role.id},
            page=f"/admin/users/{self.disabled_admin.id}",
            follow_redirects=True,
        )
        self.assertIn("is now User.", self.page_text(response))
        db.session.refresh(self.disabled_admin)
        self.assertEqual(self.disabled_admin.role.name, "User")

    def test_strip_admin_from_shared_role_is_blocked(self):
        """Removing ADMIN from a role that holds the only admins must fail."""
        ops_admin_role = Role(
            name="OpsAdmin",
            permissions=Permission.MANAGE_USERS | Permission.ADMIN | Permission.VIEW_AUDIT,
        )
        db.session.add(ops_admin_role)
        db.session.commit()
        u1 = self.make_user(email="oa1@example.com", username="oa1", role=ops_admin_role)
        self.make_user(email="oa2@example.com", username="oa2", role=ops_admin_role)
        # Demote root so OpsAdmin becomes the only role carrying ADMIN;
        # otherwise the guard correctly lets the strip through.
        self.admin.role = Role.query.filter_by(name="User").first()
        db.session.commit()

        self.login(email=u1.email)
        response = self.post_form(
            f"/admin/roles/{ops_admin_role.id}/edit",
            # RoleForm uses per-permission boolean checkboxes; omitting
            # `admin` is what strips the ADMIN permission.
            {"name": "OpsAdmin", "manage_users": "y", "view_audit": "y"},
            page=f"/admin/roles/{ops_admin_role.id}/edit",
            follow_redirects=True,
        )
        self.assertIn(
            "Cannot remove the ADMIN permission from the last administrator role.",
            self.page_text(response),
        )
        db.session.refresh(ops_admin_role)
        self.assertTrue(ops_admin_role.has_admin)

    def test_delete_last_active_admin_blocked_despite_disabled_admin(self):
        self.login(email=self.ops.email)
        response = self.post_form(
            f"/admin/users/{self.admin.id}",
            {"action": "delete_user"},
            page=f"/admin/users/{self.admin.id}",
            follow_redirects=True,
        )
        self.assertIn("Cannot delete the last administrator.", self.page_text(response))
        db.session.refresh(self.admin)
        self.assertIsNone(self.admin.deleted_at)


class FormInputPreservationTestCase(IAMTestCase):
    """Failed validation must keep what the user typed, not the old values."""

    def setUp(self):
        super().setUp()
        self.user = self.make_user(email="author@example.com", username="author")
        self.user.name = "Old Name"
        self.user.about_me = "old about text"
        post = Post(body="Original post body UNIQUEORIG", author=self.user)
        db.session.add(post)
        db.session.commit()
        self.post_id = post.id

    def test_edit_profile_keeps_submitted_values_on_failed_validation(self):
        self.login(email=self.user.email)
        response = self.post_form(
            "/edit-profile",
            {"name": "x" * 65, "location": "", "about_me": "typed about me"},
            page="/edit-profile",
        )
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        self.assertIn("typed about me", text)
        self.assertNotIn("old about text", text)

    def test_edit_post_keeps_submitted_text_on_failed_validation(self):
        self.login(email=self.user.email)
        response = self.post_form(
            f"/edit/{self.post_id}",
            {"body": ""},
            page=f"/edit/{self.post_id}",
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Original post body UNIQUEORIG", response.get_data(as_text=True))
        db.session.refresh(self.user.posts.first())
        self.assertEqual(self.user.posts.first().body, "Original post body UNIQUEORIG")


class LikeEscapingTestCase(IAMTestCase):
    """``%`` and ``_`` in search terms match literally, not as wildcards."""

    def setUp(self):
        super().setUp()
        self.author = self.make_user(email="seller@example.com", username="seller")
        db.session.add(Post(body="promotion 100% REALDEAL here", author=self.author))
        db.session.add(Post(body="1000 followers milestone", author=self.author))
        db.session.add(Post(body="under_score matchme", author=self.author))
        db.session.add(Post(body="underXscore nomatch", author=self.author))
        db.session.commit()

    def test_search_escapes_wildcards(self):
        response = self.client.get("/search?q=100%25")
        text = response.get_data(as_text=True)
        self.assertIn("promotion 100% REALDEAL here", text)
        self.assertNotIn("1000 followers milestone", text)

        response = self.client.get("/search?q=under_score")
        text = response.get_data(as_text=True)
        self.assertIn("under_score matchme", text)
        self.assertNotIn("underXscore nomatch", text)

    def test_admin_user_filter_escapes_wildcards(self):
        self.make_user(email="pct@example.com", username="pct100%user")
        self.make_user(email="plain@example.com", username="plain1000user")
        admin = self.make_user(email="root@example.com", username="root", role=self.admin_role())
        self.login(email=admin.email)
        response = self.client.get("/admin/users?q=100%25")
        text = response.get_data(as_text=True)
        self.assertIn("pct100%user", text)
        self.assertNotIn("plain1000user", text)


class ThemedErrorPagesTestCase(IAMTestCase):
    """400/404/405/429 render the shared themed page instead of raw text."""

    def setUp(self):
        super().setUp()
        self.user = self.make_user(email="viewer@example.com", username="viewer")

    def test_404_renders_shared_error_page(self):
        response = self.client.get("/definitely-missing-page")
        self.assertEqual(response.status_code, 404)
        text = response.get_data(as_text=True)
        self.assertIn("error-card", text)
        self.assertIn("Page Not Found", text)
        self.assertIn("navbar", text)  # navbar present: extends base.html

    def test_405_renders_shared_error_page(self):
        response = self.client.post(f"/user/{self.user.username}", data={})
        self.assertEqual(response.status_code, 405)
        text = response.get_data(as_text=True)
        self.assertIn("error-card", text)
        self.assertIn("Method Not Allowed", text)

    def test_400_csrf_failure_renders_shared_error_page(self):
        response = self.client.post("/auth/login", data={"email": "a@b.c", "password": "x"})
        self.assertEqual(response.status_code, 400)
        text = response.get_data(as_text=True)
        self.assertIn("error-card", text)
        self.assertIn("Bad Request", text)

    def test_429_renders_shared_error_page(self):
        limiter.reset()
        token = self.get_csrf("/")
        for i in range(10):
            self.client.post(
                "/auth/register",
                headers={"X-CSRFToken": token},
                data={
                    "email": f"rl_{i}@example.com",
                    "username": f"rluser{i}",
                    "password": "Password123!",
                    "password2": "Password123!",
                },
            )
        response = self.client.post(
            "/auth/register",
            headers={"X-CSRFToken": token},
            data={
                "email": "rl_over@example.com",
                "username": "rlover",
                "password": "Password123!",
                "password2": "Password123!",
            },
        )
        self.assertEqual(response.status_code, 429)
        text = response.get_data(as_text=True)
        self.assertIn("error-card", text)
        self.assertIn("Too Many Requests", text)
        limiter.reset()

    def test_unconfirmed_user_still_receives_404_page(self):
        """Regression: the unconfirmed gate used to hijack 404/405 pages."""
        unconfirmed = self.make_user(
            email="pending@example.com", username="pending", confirmed=False
        )
        self.login(email=unconfirmed.email)
        response = self.client.get("/definitely-missing-page")
        self.assertEqual(response.status_code, 404)
        self.assertIn("Page Not Found", response.get_data(as_text=True))


class FlashCategoryTestCase(IAMTestCase):
    """Flash categories map to distinct alert classes."""

    def setUp(self):
        super().setUp()
        self.user = self.make_user(email="flash@example.com", username="flasher")

    def test_error_flash_uses_alert_danger(self):
        response = self.post_form(
            "/auth/login",
            {"email": self.user.email, "password": "wrong-password"},
            page="/auth/login",
            follow_redirects=True,
        )
        self.assertIn('class="alert alert-danger', response.get_data(as_text=True))

    def test_success_flash_uses_alert_success(self):
        self.login(email=self.user.email)
        response = self.post_form(
            "/edit-profile",
            {"name": "Fresh Name", "location": "", "about_me": ""},
            page="/edit-profile",
            follow_redirects=True,
        )
        self.assertIn('class="alert alert-success', response.get_data(as_text=True))


class AnonymousNavigationTestCase(IAMTestCase):
    """Anonymous users get working tabs/links and explicit POST handling."""

    def test_all_tab_links_home_and_register_is_present(self):
        response = self.client.get("/")
        text = response.get_data(as_text=True)
        self.assertIn('href="/"', text)  # All tab points at main.index
        self.assertIn("/auth/register", text)  # Register link in navbar

    def test_anonymous_post_to_index_redirects_to_login(self):
        token = self.get_csrf("/")
        response = self.client.post(
            "/",
            headers={"X-CSRFToken": token},
            data={"body": "anonymous post attempt"},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers.get("Location", ""))
        self.assertEqual(Post.query.count(), 0)


class SelfFollowGuardTestCase(IAMTestCase):
    """Self-follow/unfollow is blocked, keeping profile counts sane."""

    def setUp(self):
        super().setUp()
        self.user = self.make_user(email="solo@example.com", username="solo")
        self.other = self.make_user(email="other@example.com", username="other")

    def test_self_follow_and_unfollow_are_blocked(self):
        # Every user auto-gets one self-follow (models._auto_self_follow),
        # so the baseline count is 1 and must stay untouched.
        self.login(email=self.user.email)
        response = self.post_form(
            f"/follow/{self.user.username}",
            {},
            page=f"/user/{self.user.username}",
            follow_redirects=True,
        )
        self.assertIn("You cannot follow yourself.", self.page_text(response))
        self.assertEqual(self.user.followers.count(), 1)

        response = self.post_form(
            f"/unfollow/{self.user.username}",
            {},
            page=f"/user/{self.user.username}",
            follow_redirects=True,
        )
        self.assertIn("You cannot unfollow yourself.", self.page_text(response))
        self.assertEqual(self.user.followed.count(), 1)

    def test_normal_follow_still_works_and_badge_excludes_self_follow(self):
        self.login(email=self.user.email)
        self.post_form(
            f"/follow/{self.other.username}",
            {},
            page=f"/user/{self.other.username}",
            follow_redirects=True,
        )
        # self-follow + this follow = 2; the badge subtracts the self-follow.
        self.assertEqual(self.other.followers.count(), 2)
        text = self.client.get(f"/user/{self.other.username}").get_data(as_text=True)
        self.assertIn('class="badge">1</span>', text)


class ModerationAuditTestCase(IAMTestCase):
    """Comment moderation flashes success and writes an audit event."""

    def setUp(self):
        super().setUp()
        self.author = self.make_user(email="auth@example.com", username="authr")
        self.commenter = self.make_user(email="cmt@example.com", username="cmtr")
        moderator_role = Role.query.filter_by(name="Moderator").first()
        self.moderator = self.make_user(
            email="mod@example.com", username="modr", role=moderator_role
        )
        post = Post(body="Post to moderate", author=self.author)
        db.session.add(post)
        db.session.commit()
        comment = Comment(body="A comment", post=post, author=self.commenter)
        db.session.add(comment)
        db.session.commit()
        self.comment_id = comment.id

    def test_disable_and_enable_flash_and_audit(self):
        self.login(email=self.moderator.email)
        response = self.post_form(
            f"/moderate/disable/{self.comment_id}",
            {},
            page="/moderate",
            follow_redirects=True,
        )
        self.assertIn("Comment disabled.", self.page_text(response))
        event = AuditEvent.query.filter_by(
            event=Event.COMMENT_MODERATED, target_id=self.comment_id
        ).first()
        self.assertIsNotNone(event)
        self.assertEqual(event.actor_id, self.moderator.id)

        response = self.post_form(
            f"/moderate/enable/{self.comment_id}",
            {},
            page="/moderate",
            follow_redirects=True,
        )
        self.assertIn("Comment enabled.", self.page_text(response))
        self.assertEqual(
            AuditEvent.query.filter_by(
                event=Event.COMMENT_MODERATED, target_id=self.comment_id
            ).count(),
            2,
        )


class TombstoneGuardTestCase(IAMTestCase):
    """Deleted (tombstoned) accounts cannot be edited and never crash."""

    def setUp(self):
        super().setUp()
        self.admin = self.make_user(
            email="root@example.com", username="root", role=self.admin_role()
        )
        self.gone = self.make_user(email="gone@example.com", username="gone")
        self.gone.anonymize()
        db.session.commit()

    def test_admin_edit_profile_blocked_for_deleted_account(self):
        self.login(email=self.admin.email)
        response = self.post_form(
            f"/edit-profile/{self.gone.id}",
            {
                "email": self.gone.email,
                "username": self.gone.username,
                "confirmed": "y",
                "role": self.gone.role_id,
                "name": "Should not apply",
            },
            # GET /edit-profile/<id> redirects for deleted accounts, so the
            # CSRF token has to come from a page that renders.
            page=f"/user/{self.admin.username}",
            follow_redirects=True,
        )
        self.assertIn(
            "This account has been deleted; no further changes are possible.",
            self.page_text(response),
        )
        db.session.refresh(self.gone)
        self.assertIsNone(self.gone.name)

    def test_tombstoned_user_password_verification_is_false_not_crash(self):
        self.assertFalse(self.gone.verify_password("Password123!"))
        self.assertFalse(self.gone.verify_password(""))


class PaginationGuardTestCase(IAMTestCase):
    """The pagination widget is hidden while there is only one page."""

    def setUp(self):
        super().setUp()
        self.user = self.make_user(email="pager@example.com", username="pager")
        db.session.add(Post(body="Only post", author=self.user))
        db.session.commit()

    def test_single_page_hides_pagination_widget(self):
        for path in ("/", f"/user/{self.user.username}"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('<ul class="pagination"', response.get_data(as_text=True))


class MFADisableNoopTestCase(IAMTestCase):
    """Disabling MFA that is already off reports a no-op, not success."""

    def setUp(self):
        super().setUp()
        self.user = self.make_user(email="nomfa@example.com", username="nomfa")

    def test_disable_without_mfa_enabled_is_info_noop(self):
        self.login(email=self.user.email)
        response = self.post_form(
            "/auth/security/mfa/disable",
            {"password": "Password123!"},
            page="/auth/security",
            follow_redirects=True,
        )
        text = self.page_text(response)
        self.assertIn("Two-factor authentication is not enabled.", text)
        self.assertNotIn("Two-factor authentication has been disabled.", text)


class AnonymousPostCommentTestCase(IAMTestCase):
    """Every anonymous comment POST bounces to login, valid or not."""

    def setUp(self):
        super().setUp()
        self.author = self.make_user(email="bauth@example.com", username="bauthr")
        post = Post(body="Post for anon comments", author=self.author)
        db.session.add(post)
        db.session.commit()
        self.post_id = post.id

    def test_invalid_anonymous_post_still_redirects_to_login(self):
        token = self.get_csrf("/")
        response = self.client.post(
            f"/post/{self.post_id}",
            headers={"X-CSRFToken": token},
            data={"body": ""},
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/auth/login", response.headers.get("Location", ""))
        self.assertEqual(Comment.query.count(), 0)


class ButtonMapCleanupTestCase(IAMTestCase):
    """Forms no longer render the bogus ``btn-btn`` class from button_map."""

    def test_login_submit_has_proper_button_classes(self):
        text = self.client.get("/auth/login").get_data(as_text=True)
        self.assertIn('class="btn btn-primary btn-block"', text)
        self.assertNotIn("btn-btn", text)

    def test_error_page_uses_theme_not_hardcoded_white(self):
        """Regression: the old error pages hardcoded a white background."""
        text = self.client.get("/no-such-page-anywhere").get_data(as_text=True)
        self.assertIn("style.css", text)  # theme stylesheet linked
        self.assertNotIn("background-color: #f8f9fa;", text)  # old hardcoded bg
