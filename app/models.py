import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone

import bleach
from flask import current_app, request
from flask_login import AnonymousUserMixin, UserMixin
from itsdangerous import BadSignature, TimestampSigner
from markdown import markdown
from werkzeug.security import check_password_hash, generate_password_hash

from . import db, login_manager

CONFIRMATION_TOKEN_SALT = "confirmation-token"
AUTH_TOKEN_SALT = "api-auth-token"
CHANGE_EMAIL_TOKEN_SALT = "change-email-token"
RESET_PASSWORD_TOKEN_SALT = "password-reset-token"


class Permission:
    FOLLOW = 1
    COMMENT = 2
    WRITE = 4
    MODERATE = 8
    ADMIN = 16


class Role(db.Model):
    __tablename__ = "roles"
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

    def __repr__(self):
        return f"<Role {self.name}>"


class Follow(db.Model):
    __tablename__ = "follows"
    follower_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
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

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config["BLOGG_ADMIN"]:
                self.role = Role.query.filter_by(name="Administrator").first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = self.gravatar_hash()
        self.follow(self)

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

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

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

        user.password = password
        db.session.add(user)
        db.session.commit()
        return True

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
            db.session.commit()  # Commit the change

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)
            db.session.commit()  # Commit the change

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
        token = signer.sign(str(self.id))
        return token.decode("utf-8")

    @staticmethod
    def verify_auth_token(token, max_age=3600):
        if not token:
            return None
        signer = TimestampSigner(current_app.config["SECRET_KEY"], salt=AUTH_TOKEN_SALT)
        try:
            data = signer.unsign(token, max_age=max_age)
            user_id = int(data.decode("utf-8"))
        except (BadSignature, ValueError):
            return None
        return db.session.get(User, user_id)

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


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


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
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
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
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), index=True)
    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), index=True)

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
