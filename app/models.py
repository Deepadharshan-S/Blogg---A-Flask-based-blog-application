import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone

import bleach
import pyotp
from flask import current_app, request
from flask_login import AnonymousUserMixin, UserMixin
from itsdangerous import BadSignature, TimestampSigner
from markdown import markdown
from sqlalchemy import event
from sqlalchemy.orm import validates
from werkzeug.security import check_password_hash, generate_password_hash

from . import db, login_manager

CONFIRMATION_TOKEN_SALT = "confirmation-token"
AUTH_TOKEN_SALT = "api-auth-token"
CHANGE_EMAIL_TOKEN_SALT = "change-email-token"
RESET_TOKEN_SALT = "password-reset-token"
RESET_PASSWORD_TOKEN_SALT = RESET_TOKEN_SALT


def utc_now():
    """Timezone-aware UTC timestamp (consistent with existing column defaults)."""
    return datetime.now(timezone.utc)


def as_naive_utc(dt):
    """Normalize a possibly timezone-aware datetime to naive UTC for safe comparisons.

    SQLite returns naive datetimes even when aware values were stored, so every
    Python-side comparison must normalize first.
    """
    if dt is None:
        return None
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16
    MANAGE_USERS = 32
    VIEW_AUDIT = 64

    @staticmethod
    def all():
        """Mapping of every permission name to its bitmask value."""
        return {
            "FOLLOW": Permission.FOLLOW,
            "COMMENT": Permission.COMMENT,
            "WRITE": Permission.WRITE,
            "MODERATE": Permission.MODERATE,
            "ADMIN": Permission.ADMIN,
            "MANAGE_USERS": Permission.MANAGE_USERS,
            "VIEW_AUDIT": Permission.VIEW_AUDIT,
        }

    @staticmethod
    def names():
        return list(Permission.all().keys())


class Role(db.Model):
    __tablename__ = "roles"
    # Roles seeded by insert_roles(); they cannot be renamed or deleted.
    BUILTIN_NAMES = ("User", "Moderator", "Administrator")

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship("User", backref="role", lazy="dynamic")

    def __init__(self, **kwargs):
        super(Role, self).__init__(**kwargs)
        if self.permissions is None:
            self.permissions = 0

    def add_permission(self, perm):
        if not self.has_permission(perm):
            self.permissions += perm

    def remove_permission(self, perm):
        if self.has_permission(perm):
            self.permissions -= perm

    def reset_permissions(self):
        self.permissions = 0

    def has_permission(self, perm):
        return self.permissions & perm == perm

    @staticmethod
    def insert_roles():
        roles = {
            "User": [Permission.FOLLOW, Permission.COMMENT, Permission.WRITE],
            "Moderator": [
                Permission.FOLLOW,
                Permission.COMMENT,
                Permission.WRITE,
                Permission.MODERATE,
            ],
            "Administrator": [
                Permission.FOLLOW,
                Permission.COMMENT,
                Permission.WRITE,
                Permission.MODERATE,
                Permission.ADMIN,
                Permission.MANAGE_USERS,
                Permission.VIEW_AUDIT,
            ],
        }
        default_role = "User"
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.reset_permissions()
            for perm in roles[r]:
                role.add_permission(perm)
            role.default = role.name == default_role
            db.session.add(role)
        db.session.commit()

    @staticmethod
    def permission_names(permissions):
        """Return the list of permission names contained in a bitmask."""
        return [
            name
            for name, value in Permission.all().items()
            if permissions is not None and permissions & value == value
        ]

    @staticmethod
    def permission_value(names):
        """Combine a list of permission names into a bitmask. Unknown names raise ValueError."""
        valid = Permission.all()
        value = 0
        for name in names:
            if name not in valid:
                raise ValueError(f"Unknown permission: {name}")
            value |= valid[name]
        return value

    @property
    def user_count(self):
        return self.users.count()

    @property
    def is_builtin(self):
        return self.name in Role.BUILTIN_NAMES

    @property
    def has_admin(self):
        return self.permissions is not None and self.permissions & Permission.ADMIN != 0

    def to_json(self):
        return {
            "id": self.id,
            "name": self.name,
            "default": bool(self.default),
            "permissions": self.permissions,
            "permission_names": Role.permission_names(self.permissions),
            "user_count": self.user_count,
        }

    def __repr__(self):
        return f"<Role {self.name}>"


class Follow(db.Model):
    __tablename__ = "follows"
    follower_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    followed_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class PostLike(db.Model):
    __tablename__ = "post_likes"
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id", ondelete="CASCADE"), primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), index=True)
    confirmed = db.Column(db.Boolean, default=False)
    # --- IAM: account lifecycle & authentication state ---
    active = db.Column(db.Boolean, default=True, nullable=False)
    # IAM: admin-issued forced password change (B1). While set, web requests
    # are redirected to the change-password form and API credentials return
    # 403 until a new password is set (which clears the flag).
    must_change_password = db.Column(db.Boolean, default=False, nullable=False)
    locked_until = db.Column(db.DateTime())
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    mfa_secret = db.Column(db.String(64))
    mfa_backup_codes = db.Column(db.Text())  # JSON list of SHA-256 hashes
    password_changed_at = db.Column(db.DateTime())
    last_login_at = db.Column(db.DateTime())
    # IAM: cutoff stamped by any full session revocation (A4). Every Flask-Login
    # identity issued before this instant carries an older epoch tag and is
    # refused by load_user() — including remember-me cookies, which never have
    # a server-side session row to revoke.
    sessions_revoked_at = db.Column(db.DateTime())
    # IAM: tombstone timestamp (B3). A deleted account keeps its row (and its
    # posts) so community content survives; anonymize() strips every trace of
    # the person behind it and stamps this.
    deleted_at = db.Column(db.DateTime())
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime(), default=lambda: datetime.now(timezone.utc))
    avatar_hash = db.Column(db.String(32))
    posts = db.relationship(
        "Post",
        backref="author",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    followed = db.relationship(
        "Follow",
        foreign_keys=[Follow.follower_id],
        backref=db.backref("follower", lazy="joined"),
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    followers = db.relationship(
        "Follow",
        foreign_keys=[Follow.followed_id],
        backref=db.backref("followed", lazy="joined"),
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    comments = db.relationship(
        "Comment",
        backref="author",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    liked_posts = db.relationship(
        "PostLike",
        foreign_keys=[PostLike.user_id],
        backref=db.backref("user", lazy="joined"),
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    password_history = db.relationship(
        "PasswordHistory",
        backref="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
        order_by="PasswordHistory.timestamp.desc()",
    )
    sessions = db.relationship(
        "UserSession",
        backref="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    api_tokens = db.relationship(
        "ApiToken",
        backref="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    @validates("email")
    def validate_email_field(self, key, address):
        if address is not None:
            return address.strip().lower()
        return address

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            with db.session.no_autoflush:
                admin_email = current_app.config.get("BLOGG_ADMIN")
                if admin_email and self.email == admin_email.strip().lower():
                    self.role = Role.query.filter_by(name="Administrator").first()
                if self.role is None:
                    self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()
        if self.active is None:
            self.active = True
        if self.failed_login_attempts is None:
            self.failed_login_attempts = 0
        if self.mfa_enabled is None:
            self.mfa_enabled = False
        if self.password_changed_at is None:
            self.password_changed_at = datetime.now(timezone.utc)

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
        db.session.commit()

    @property
    def password(self):
        raise AttributeError("password is not a readable attribute")

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
        self.password_changed_at = utc_now()

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    # ------------------------------------------------------------------
    # IAM: account state (lockout, disable) & password policy
    # ------------------------------------------------------------------
    @property
    def is_active(self):
        """Flask-Login hook: disabled accounts cannot log in."""
        return bool(self.active)

    @property
    def is_locked(self):
        """True while a brute-force lockout is in effect."""
        if self.locked_until is None:
            return False
        return as_naive_utc(self.locked_until) > as_naive_utc(utc_now())

    def lock(self, minutes=None):
        if minutes is None:
            minutes = current_app.config["BLOGG_LOCKOUT_MINUTES"]
        self.locked_until = utc_now() + timedelta(minutes=minutes)

    def unlock(self):
        self.locked_until = None
        self.failed_login_attempts = 0

    def record_failed_login(self):
        """Increment the failure counter; returns True when the account just got locked."""
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        max_failures = current_app.config["BLOGG_MAX_FAILED_LOGINS"]
        if self.failed_login_attempts >= max_failures:
            self.lock()
            return True
        return False

    def reset_login_failures(self):
        self.failed_login_attempts = 0
        self.locked_until = None

    def push_password_history(self):
        """Archive the current hash so future passwords cannot be reused."""
        count = current_app.config["BLOGG_PASSWORD_HISTORY_COUNT"]
        if count <= 0:
            return
        db.session.add(PasswordHistory(user=self, password_hash=self.password_hash))
        db.session.flush()
        # Trim old entries beyond the configured history depth.
        entries = self.password_history.limit(count + 1).all()
        for stale in entries[count:]:
            db.session.delete(stale)

    def is_password_reused(self, new_password):
        """True when new_password matches the current or a recently used password."""
        if self.password_hash and check_password_hash(self.password_hash, new_password):
            return True
        count = current_app.config["BLOGG_PASSWORD_HISTORY_COUNT"]
        for entry in self.password_history.limit(count):
            if check_password_hash(entry.password_hash, new_password):
                return True
        return False

    # ------------------------------------------------------------------
    # IAM: multi-factor authentication (TOTP + one-time backup codes)
    # ------------------------------------------------------------------
    @staticmethod
    def normalize_backup_code(code):
        return (code or "").strip().lower().replace("-", "").replace(" ", "")

    def generate_mfa_secret(self):
        self.mfa_secret = pyotp.random_base32()
        return self.mfa_secret

    def mfa_provisioning_uri(self):
        if not self.mfa_secret:
            return None
        return pyotp.TOTP(self.mfa_secret).provisioning_uri(
            name=self.email, issuer_name=current_app.config["BLOGG_MFA_ISSUER"]
        )

    def generate_backup_codes(self, total=10):
        codes = []
        digests = []
        for _ in range(total):
            raw = secrets.token_hex(4)  # 8 hex chars
            code = f"{raw[:4]}-{raw[4:]}"
            codes.append(code)
            digests.append(hashlib.sha256(self.normalize_backup_code(code).encode()).hexdigest())
        self.mfa_backup_codes = json.dumps(digests)
        return codes

    def backup_code_hashes(self):
        if not self.mfa_backup_codes:
            return []
        try:
            return json.loads(self.mfa_backup_codes)
        except ValueError:
            return []

    def consume_backup_code(self, code):
        """Consume a one-time backup code (hashed at rest). Returns True on match."""
        digests = self.backup_code_hashes()
        digest = hashlib.sha256(self.normalize_backup_code(code).encode()).hexdigest()
        if digest in digests:
            digests.remove(digest)
            self.mfa_backup_codes = json.dumps(digests)
            return True
        return False

    def verify_mfa_code(self, code):
        """Accept either a live TOTP code or an unused backup code."""
        if not self.mfa_secret:
            return False
        cleaned = (code or "").strip().replace(" ", "")
        if not cleaned:
            return False
        if pyotp.TOTP(self.mfa_secret).verify(cleaned, valid_window=1):
            return True
        return self.consume_backup_code(cleaned)

    def disable_mfa(self):
        self.mfa_enabled = False
        self.mfa_secret = None
        self.mfa_backup_codes = None

    # ------------------------------------------------------------------
    # IAM: session revocation (password-reset token logic lives with the
    # fingerprint-bound implementation below so tokens stay single-use)
    # ------------------------------------------------------------------
    @staticmethod
    def parse_identity(user_id):
        """Split a Flask-Login identity ``"id[.cutoff_epoch]"`` -> (id, epoch).

        Returns (None, 0) when the payload is not a usable identity.
        """
        id_part, _, epoch_part = str(user_id or "").partition(".")
        try:
            user_pk = int(id_part)
            epoch = int(epoch_part) if epoch_part else 0
        except ValueError:
            return None, 0
        return user_pk, epoch

    def sessions_cutoff_epoch(self):
        """Epoch seconds of the sessions_revoked_at cutoff (0 when unset)."""
        ts = self.sessions_revoked_at
        if ts is None:
            return 0
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return int(ts.timestamp())

    def get_id(self):
        """Flask-Login identity tagged with the revocation cutoff in force.

        Both the session's ``_user_id`` and the remember-me cookie carry this
        value at issue time; load_user() refuses any identity whose tag no
        longer matches the user's current cutoff, so a revocation kills old
        remember-me cookies along with sessions.
        """
        return f"{self.id}.{self.sessions_cutoff_epoch()}"

    def revoke_sessions(self, keep_jti=None):
        """Revoke active sessions except keep_jti and stamp the A4 cutoff.

        The cutoff invalidates every previously issued identity (session and
        remember-me alike) even for rows the sweep does not touch.
        Returns the number of session rows revoked.
        """
        now = utc_now()
        self.sessions_revoked_at = now
        db.session.add(self)
        revoked = 0
        for session_row in self.sessions:
            if session_row.revoked_at is None and session_row.jti != keep_jti:
                session_row.revoked_at = now
                db.session.add(session_row)
                revoked += 1
        return revoked

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)

    def __repr__(self):
        return f"<User {self.username}>"

    def ping(self):
        self.last_seen = datetime.now(timezone.utc)
        db.session.add(self)
        db.session.commit()

    def generate_confirmation_token(self, expiration=3600):
        signer = TimestampSigner(current_app.config["SECRET_KEY"], salt=CONFIRMATION_TOKEN_SALT)
        token = signer.sign(str(self.id))
        return token.decode("utf-8")

    def generate_email_change_token(self, new_email, expiration=3600):
        signer = TimestampSigner(current_app.config["SECRET_KEY"], salt=CHANGE_EMAIL_TOKEN_SALT)
        new_email = (new_email or "").strip().lower()
        # Prepare the payload
        data = {"change_email": self.id, "new_email": new_email}
        # Encode data to base64 JSON string
        json_data = json.dumps(data).encode("utf-8")
        base64_data = base64.urlsafe_b64encode(json_data).decode("utf-8")

        # Sign the payload with timestamp
        signed_value = signer.sign(base64_data.encode("utf-8"))
        return signed_value.decode("utf-8")

    def change_email(self, token, expiration=3600):
        if not token:
            return False
        signer = TimestampSigner(current_app.config["SECRET_KEY"], salt=CHANGE_EMAIL_TOKEN_SALT)

        try:
            # Unsign token with expiration
            unsigned = signer.unsign(token, max_age=expiration)
            base64_data = unsigned.decode("utf-8")
            json_data = base64.urlsafe_b64decode(base64_data.encode("utf-8"))
            data = json.loads(json_data.decode("utf-8"))
        except (BadSignature, ValueError):
            return False

        if data.get("change_email") != self.id:
            return False

        new_email = data.get("new_email")
        if not new_email:
            return False
        new_email = new_email.strip().lower()

        if self.query.filter_by(email=new_email).first() is not None:
            return False

        self.email = new_email
        self.avatar_hash = self.gravatar_hash()
        db.session.add(self)
        return True

    def confirm(self, token, expiration=3600):
        if not token:
            return False
        signer = TimestampSigner(current_app.config["SECRET_KEY"], salt=CONFIRMATION_TOKEN_SALT)
        try:
            user_id = signer.unsign(token, max_age=expiration).decode("utf-8")
        except (BadSignature, ValueError):
            return False

        if user_id != str(self.id):
            return False

        self.confirmed = True
        db.session.add(self)
        return True

    def anonymize(self):
        """Tombstone the account (B3): strip identity, credentials and MFA.

        Content the user authored (posts, comments, likes, follows) stays
        attached to this row so community history survives; nothing
        identifies the person behind it any more. The username/email derived
        from the immutable id stay unique forever, and the person's original
        handle is freed for re-registration. Callers revoke sessions and
        record the audit event themselves.
        """
        self.username = f"deleted_{self.id}"
        self.email = f"deleted_{self.id}@example.invalid"  # RFC 2606 TLD
        self.name = None
        self.location = None
        self.about_me = None
        self.avatar_hash = self.gravatar_hash()
        # Credentials die: no password, deactivated, demoted to the default
        # role so the account no longer counts toward last-admin guards.
        self.password_hash = None
        self.must_change_password = False
        self.active = False
        self.confirmed = False
        self.role = Role.query.filter_by(default=True).first()
        # MFA dies with the account.
        self.mfa_enabled = False
        self.mfa_secret = None
        self.mfa_backup_codes = None
        # Nothing may keep acting as this user: kill API tokens and archived
        # password hashes outright (the relationships would cascade them on a
        # hard delete, but the row itself survives, so clear them here).
        ApiToken.query.filter_by(user_id=self.id).delete(synchronize_session=False)
        PasswordHistory.query.filter_by(user_id=self.id).delete(synchronize_session=False)
        self.deleted_at = utc_now()
        db.session.add(self)
        return self

    def generate_reset_token(self, expiration=None):
        signer = TimestampSigner(current_app.config["SECRET_KEY"], salt=RESET_PASSWORD_TOKEN_SALT)
        pw_fingerprint = hashlib.sha256((self.password_hash or "").encode("utf-8")).hexdigest()[:16]
        data = {"reset": self.id, "hash": pw_fingerprint}
        json_data = json.dumps(data).encode("utf-8")
        base64_data = base64.urlsafe_b64encode(json_data).decode("utf-8")
        signed_value = signer.sign(base64_data.encode("utf-8"))
        return signed_value.decode("utf-8")

    @staticmethod
    def reset_password(token, password, expiration=None):
        if not token or not isinstance(token, (str, bytes)) or not password:
            return False

        signer = TimestampSigner(current_app.config["SECRET_KEY"], salt=RESET_PASSWORD_TOKEN_SALT)
        max_age = (
            expiration
            if expiration is not None
            else current_app.config.get("RESET_PASSWORD_TOKEN_MAX_AGE", 1800)
        )
        try:
            unsigned = signer.unsign(token, max_age=max_age)
            base64_data = unsigned.decode("utf-8")
            json_data = base64.urlsafe_b64decode(base64_data.encode("utf-8"))
            data = json.loads(json_data.decode("utf-8"))
        except (BadSignature, ValueError):
            return False

        if not isinstance(data, dict):
            return False

        try:
            user_id = int(data.get("reset"))
        except (ValueError, TypeError):
            return False

        token_hash = data.get("hash")
        if not token_hash or not isinstance(token_hash, str):
            return False

        user = db.session.get(User, user_id)
        if user is None:
            return False

        current_fingerprint = hashlib.sha256(
            (user.password_hash or "").encode("utf-8")
        ).hexdigest()[:16]
        if not hmac.compare_digest(current_fingerprint, token_hash):
            return False

        # IAM: archive the outgoing hash (reuse prevention) and clear any
        # lockout state before the password setter overwrites the hash.
        user.push_password_history()
        user.password = password
        user.reset_login_failures()
        # Completing a reset is a fresh credential: it satisfies any forced
        # password change (B1) an admin had issued.
        user.must_change_password = False
        db.session.add(user)
        db.session.commit()
        # Return the user (truthy) so callers can revoke sessions / audit it.
        return user

    def gravatar_hash(self):
        return hashlib.md5(self.email.lower().encode("utf-8")).hexdigest()

    def gravatar(self, size=100, default="identicon", rating="g"):
        if request.is_secure:
            url = "https://secure.gravatar.com/avatar"
        else:
            url = "http://www.gravatar.com/avatar"
        hash = self.avatar_hash or self.gravatar_hash()
        return "{url}/{hash}?s={size}&d={default}&r={rating}".format(
            url=url, hash=hash, size=size, default=default, rating=rating
        )

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        if user.id is None:
            return False
        return self.followed.filter_by(followed_id=user.id).first() is not None

    def is_followed_by(self, user):  # Corrected method
        if user.id is None:
            return False
        return self.followers.filter_by(follower_id=user.id).first() is not None

    @property
    def followed_posts(self):
        return Post.query.join(Follow, Follow.followed_id == Post.author_id).filter(
            Follow.follower_id == self.id
        )

    def like_post(self, post):
        if not self.has_liked_post(post):
            like = PostLike(user=self, post=post)
            db.session.add(like)

    def unlike_post(self, post):
        like = self.liked_posts.filter_by(post_id=post.id).first()
        if like:
            db.session.delete(like)

    def has_liked_post(self, post):
        if post.id is None:
            return False
        return self.liked_posts.filter_by(post_id=post.id).first() is not None

    def generate_auth_token(self, expiration=3600):
        signer = TimestampSigner(current_app.config["SECRET_KEY"], salt=AUTH_TOKEN_SALT)
        pw_fingerprint = hashlib.sha256((self.password_hash or "").encode("utf-8")).hexdigest()[:16]
        data = {"auth": self.id, "hash": pw_fingerprint}
        json_data = json.dumps(data).encode("utf-8")
        base64_data = base64.urlsafe_b64encode(json_data).decode("utf-8")
        signed_value = signer.sign(base64_data.encode("utf-8"))
        return signed_value.decode("utf-8")

    @staticmethod
    def verify_auth_token(token, max_age=3600):
        if not token or not isinstance(token, (str, bytes)):
            return None
        signer = TimestampSigner(current_app.config["SECRET_KEY"], salt=AUTH_TOKEN_SALT)
        try:
            unsigned = signer.unsign(token, max_age=max_age)
            base64_data = unsigned.decode("utf-8")
            json_data = base64.urlsafe_b64decode(base64_data.encode("utf-8"))
            data = json.loads(json_data.decode("utf-8"))
        except (BadSignature, ValueError, Exception):
            return None

        if not isinstance(data, dict):
            return None

        try:
            user_id = int(data.get("auth"))
        except (ValueError, TypeError):
            return None

        token_hash = data.get("hash")
        if not token_hash or not isinstance(token_hash, str):
            return None

        user = db.session.get(User, user_id)
        if user is None:
            return None

        current_fingerprint = hashlib.sha256(
            (user.password_hash or "").encode("utf-8")
        ).hexdigest()[:16]
        if not hmac.compare_digest(current_fingerprint, token_hash):
            return None

        return user

    def to_json(self):
        return {
            "id": self.id,
            "username": self.username,
            "name": self.name,
            "location": self.location,
            "about_me": self.about_me,
            "member_since": self.member_since.isoformat() if self.member_since else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "posts_count": self.posts.count(),
            "followers_count": self.followers.count(),
            "following_count": self.followed.count(),
        }

    def to_admin_json(self):
        """Admin view of a user: identity + full IAM state."""
        data = self.to_json()
        data.update(
            {
                "email": self.email,
                "role": self.role.name if self.role else None,
                "permissions": self.role.permissions if self.role else 0,
                "permission_names": Role.permission_names(self.role.permissions)
                if self.role
                else [],
                "confirmed": bool(self.confirmed),
                "active": bool(self.active),
                "locked": self.is_locked,
                "locked_until": self.locked_until.isoformat() if self.locked_until else None,
                "failed_login_attempts": self.failed_login_attempts or 0,
                "mfa_enabled": bool(self.mfa_enabled),
                "password_changed_at": self.password_changed_at.isoformat()
                if self.password_changed_at
                else None,
                "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
                "must_change_password": bool(self.must_change_password),
                "deleted_at": self.deleted_at.isoformat() if self.deleted_at else None,
                "active_sessions": self.sessions.filter_by(revoked_at=None).count(),
                "active_tokens": sum(1 for t in self.api_tokens if t.is_valid),
            }
        )
        return data


@login_manager.user_loader
def load_user(user_id):
    user_pk, issued_epoch = User.parse_identity(user_id)
    if user_pk is None:
        return None
    user = db.session.get(User, user_pk)
    if user is None:
        return None
    if issued_epoch != user.sessions_cutoff_epoch():
        # Identity predates a sessions_revoked_at cutoff: the session or
        # remember-me cookie that carried it was revoked (A4). Refusing it
        # is what stops a remembered browser resurrecting a signed-out
        # account, since remember cookies have no session row to revoke.
        return None
    return user


@event.listens_for(User, "after_insert")
def _auto_self_follow(mapper, connection, target):
    """Automatically establish self-follow relationship when a user is persisted."""
    connection.execute(
        Follow.__table__.insert().values(
            follower_id=target.id,
            followed_id=target.id,
            timestamp=datetime.now(timezone.utc),
        )
    )


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False


login_manager.anonymous_user = AnonymousUser


class Post(db.Model):
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    comments = db.relationship(
        "Comment",
        backref="post",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    likes = db.relationship(
        "PostLike",
        foreign_keys=[PostLike.post_id],
        backref=db.backref("post", lazy="joined"),
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    @property
    def reading_time(self):
        words = len((self.body or "").split())
        minutes = max(1, round(words / 200))
        return f"{minutes} min read"

    def to_json(self):
        return {
            "id": self.id,
            "body": self.body,
            "body_html": self.body_html,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "author_id": self.author_id,
            "author_username": self.author.username if self.author else None,
            "comments_count": self.comments.count(),
            "likes_count": self.likes.count(),
            "reading_time": self.reading_time,
        }

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = [
            "a",
            "abbr",
            "acronym",
            "b",
            "blockquote",
            "code",
            "em",
            "i",
            "li",
            "ol",
            "pre",
            "strong",
            "ul",
            "h1",
            "h2",
            "h3",
            "p",
        ]
        processed = markdown(value, output_format="html")
        sanitized = bleach.clean(processed, tags=allowed_tags, strip=True).strip()

        if not sanitized:  # If sanitized content is empty, reject it
            target.body_html = None
        else:
            target.body_html = bleach.linkify(sanitized)


db.event.listen(Post.body, "set", Post.on_changed_body)


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), index=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id", ondelete="CASCADE"), index=True)

    def to_json(self):
        return {
            "id": self.id,
            "body": self.body,
            "body_html": self.body_html,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "author_id": self.author_id,
            "author_username": self.author.username if self.author else None,
            "post_id": self.post_id,
            "disabled": bool(self.disabled),
        }

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ["a", "abbr", "acronym", "b", "code", "em", "i", "strong"]
        target.body_html = bleach.linkify(
            bleach.clean(markdown(value, output_format="html"), tags=allowed_tags, strip=True)
        )


db.event.listen(Comment.body, "set", Comment.on_changed_body)


class AuditEvent(db.Model):
    """Structured security/audit trail (login, role change, token issue, ...)."""

    __tablename__ = "audit_events"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True, default=utc_now)
    event = db.Column(db.String(64), index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    actor_label = db.Column(db.String(128))  # email at event time (survives user deletion)
    target_type = db.Column(db.String(32))  # user | post | session | token | role | account
    target_id = db.Column(db.Integer)
    target_label = db.Column(db.String(128))
    success = db.Column(db.Boolean, default=True)
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(256))
    detail = db.Column(db.Text)  # JSON payload

    def to_json(self):
        detail = None
        if self.detail:
            try:
                detail = json.loads(self.detail)
            except ValueError:
                detail = self.detail
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event": self.event,
            "actor_id": self.actor_id,
            "actor": self.actor_label,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "target": self.target_label,
            "success": bool(self.success),
            "ip": self.ip,
            "user_agent": self.user_agent,
            "detail": detail,
        }


class PasswordHistory(db.Model):
    """Archived password hashes used to enforce password-reuse policy."""

    __tablename__ = "password_history"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    password_hash = db.Column(db.String(128))
    timestamp = db.Column(db.DateTime, default=utc_now)


class UserSession(db.Model):
    """Server-side session record: revocation, idle & absolute timeouts, device list."""

    __tablename__ = "user_sessions"
    jti = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    created_at = db.Column(db.DateTime, default=utc_now)
    last_seen_at = db.Column(db.DateTime, default=utc_now)
    expires_at = db.Column(db.DateTime)  # absolute lifetime
    revoked_at = db.Column(db.DateTime)
    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(256))

    def is_expired(self, idle_minutes, now=None):
        now = as_naive_utc(now or utc_now())
        if as_naive_utc(self.expires_at) and as_naive_utc(self.expires_at) < now:
            return True
        last_seen = as_naive_utc(self.last_seen_at)
        if last_seen and (now - last_seen).total_seconds() > idle_minutes * 60:
            return True
        return False

    @property
    def is_revoked(self):
        return self.revoked_at is not None

    def to_json(self):
        return {
            "jti": self.jti,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked": self.is_revoked,
            "ip": self.ip,
            "user_agent": self.user_agent,
        }


class ApiToken(db.Model):
    """Opaque, revocable, scoped API token (stored as a SHA-256 hash)."""

    __tablename__ = "api_tokens"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    name = db.Column(db.String(64), default="default")
    token_hash = db.Column(db.String(64), unique=True, index=True)
    scopes = db.Column(db.String(255), default="")
    created_at = db.Column(db.DateTime, default=utc_now)
    expires_at = db.Column(db.DateTime)
    last_used_at = db.Column(db.DateTime)
    revoked_at = db.Column(db.DateTime)

    # Known scope vocabulary for the blog's API.
    KNOWN_SCOPES = (
        "profile:read",
        "posts:read",
        "posts:write",
        "comments:write",
        "tokens:manage",
        "admin",
    )
    DEFAULT_SCOPES = ("profile:read", "posts:read", "posts:write", "comments:write")

    @staticmethod
    def hash_token(token):
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @property
    def scope_list(self):
        return [s for s in (self.scopes or "").split() if s]

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        return as_naive_utc(self.expires_at) < as_naive_utc(utc_now())

    @property
    def is_revoked(self):
        return self.revoked_at is not None

    @property
    def is_valid(self):
        return not self.is_revoked and not self.is_expired

    def has_scope(self, scope):
        return scope in self.scope_list

    def to_json(self):
        return {
            "id": self.id,
            "name": self.name,
            "scopes": self.scope_list,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "revoked": self.is_revoked,
            "expired": self.is_expired,
            "active": self.is_valid,
        }
