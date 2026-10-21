from urllib.parse import urlsplit

from flask import (
    abort,
    current_app,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy.orm import joinedload

from .. import db
from ..decorators import admin_required, owner_or_permission, permission_required
from ..models import Comment, Permission, Post, Role, User
from ..security import Event, administrator_count, record_audit
from . import main
from .forms import CommentForm, EditProfileAdminForm, EditProfileForm, PostForm


def is_safe_redirect_url(target):
    """Validate that a redirect target is a safe relative path or same-origin URL."""
    if not target or not isinstance(target, str):
        return False
    target = target.strip()
    if target.startswith("//") or target.startswith("/\\") or target.startswith("\\"):
        return False
    try:
        parsed = urlsplit(target)
    except ValueError:
        return False
    if not parsed.netloc and not parsed.scheme and target.startswith("/"):
        return True
    if parsed.scheme in ("http", "https") and parsed.netloc == request.host:
        return True
    return False


@main.route("/", methods=["GET", "POST"])
def index():
    form = PostForm()
    if current_user.can(Permission.WRITE) and form.validate_on_submit():
        post = Post(body=form.body.data, author=current_user._get_current_object())
        db.session.add(post)
        db.session.commit()
        current_app.logger.info(f'New post by {current_user.email}: "{form.body.data[:30]}..."')
        return redirect(url_for(".index"))
    page = request.args.get("page", 1, type=int)
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get("show_followed", ""))
    if show_followed:
        query = current_user.followed_posts.options(joinedload(Post.author))
    else:
        query = Post.query.options(joinedload(Post.author))
    pagination = query.order_by(Post.timestamp.desc()).paginate(
        page=page, per_page=current_app.config["BLOGG_POSTS_PER_PAGE"], error_out=False
    )
    posts = pagination.items
    return render_template(
        "index.html", form=form, posts=posts, pagination=pagination, show_followed=show_followed
    )


@main.route("/user/<username>")
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    page = request.args.get("page", 1, type=int)
    pagination = (
        user.posts.options(joinedload(Post.author))
        .order_by(Post.timestamp.desc())
        .paginate(page=page, per_page=current_app.config["BLOGG_POSTS_PER_PAGE"], error_out=False)
    )
    posts = pagination.items
    return render_template("user.html", user=user, posts=posts, pagination=pagination)


@main.route("/edit-profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user._get_current_object())
        db.session.commit()
        current_app.logger.info(f"User updated profile: {current_user.email}")
        flash("Your profile has been updated.")
        return redirect(url_for(".user", username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template("edit_profile.html", form=form)


@main.route("/edit-profile/<int:id>", methods=["GET", "POST"])
@login_required
@admin_required
def edit_profile_admin(id):
    user = db.get_or_404(User, id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        actor = current_user._get_current_object()
        old_role = user.role.name if user.role else None
        new_role = db.session.get(Role, form.role.data)
        new_role_name = new_role.name if new_role else None

        # Same guardrails as the admin console.
        if old_role != new_role_name:
            if user == actor:
                flash("Use another administrator account to change your own role.")
                return redirect(url_for(".edit_profile_admin", id=user.id))
            if user.can(Permission.ADMIN) and not new_role.has_admin and administrator_count() <= 1:
                flash("Cannot demote the last administrator.")
                return redirect(url_for(".edit_profile_admin", id=user.id))

        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = new_role
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        if old_role != new_role_name:
            record_audit(
                Event.USER_ROLE_CHANGED,
                actor=actor,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
                detail={"from": old_role, "to": new_role_name, "via": "edit_profile_admin"},
                commit=False,
            )
        db.session.commit()
        current_app.logger.info(
            f"Admin {current_user.email} updated profile of user {user.email} "
            f"(role: {user.role.name}, confirmed: {user.confirmed})"
        )
        flash("The profile has been updated.")
        return redirect(url_for(".user", username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template("edit_profile.html", form=form, user=user)


@main.route("/post/<int:id>", methods=["GET", "POST"])
def post(id):
    post = db.get_or_404(Post, id, options=[joinedload(Post.author)])
    form = CommentForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You must be logged in to comment.")
            return redirect(url_for("auth.login", next=url_for(".post", id=post.id)))
        if not current_user.can(Permission.COMMENT):
            abort(403)
        comment = Comment(body=form.body.data, post=post, author=current_user._get_current_object())
        db.session.add(comment)
        db.session.commit()
        current_app.logger.info(
            f'User {current_user.email} commented on post {post.id}: "{comment.body[:50]}..."'
        )
        flash("Your comment has been published.")
        return redirect(url_for(".post", id=post.id, page=-1))
    page = request.args.get("page", 1, type=int)
    if page == -1:
        page = (post.comments.count() - 1) // current_app.config["BLOGG_COMMENTS_PER_PAGE"] + 1
    pagination = (
        post.comments.options(joinedload(Comment.author))
        .order_by(Comment.timestamp.asc())
        .paginate(
            page=page, per_page=current_app.config["BLOGG_COMMENTS_PER_PAGE"], error_out=False
        )
    )
    comments = pagination.items
    return render_template(
        "post.html", posts=[post], form=form, comments=comments, pagination=pagination
    )


@main.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit(id):
    post = db.get_or_404(Post, id)
    if not owner_or_permission(current_user._get_current_object(), post):
        current_app.logger.warning(
            f"Unauthorized edit attempt by {current_user.email} on post {post.id}"
        )
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.body = form.body.data
        db.session.add(post)
        db.session.commit()
        flash("The post has been updated.")
        return redirect(url_for(".post", id=post.id))
    form.body.data = post.body
    return render_template("edit_post.html", form=form)


@main.route("/followed_by/<username>")
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash("Invalid user.")
        return redirect(url_for(".index"))
    page = request.args.get("page", 1, type=int)
    pagination = user.followed.paginate(
        page=page, per_page=current_app.config["BLOGG_FOLLOWERS_PER_PAGE"], error_out=False
    )
    follows = [{"user": item.followed, "timestamp": item.timestamp} for item in pagination.items]
    return render_template(
        "followers.html",
        user=user,
        title="Followed by",
        endpoint=".followed_by",
        pagination=pagination,
        follows=follows,
    )


@main.route("/follow/<username>", methods=["POST"])
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash("Invalid user.")
        return redirect(url_for(".index"))
    if current_user.is_following(user):
        flash("You are already following this user.")
        return redirect(url_for(".user", username=username))
    current_user.follow(user)
    db.session.commit()
    current_app.logger.info(f"{current_user.email} followed {user.email}")
    flash("You are now following %s." % username)
    return redirect(url_for(".user", username=username))


@main.route("/unfollow/<username>", methods=["POST"])
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash("Invalid user.")
        return redirect(url_for(".index"))
    if not current_user.is_following(user):
        flash("You are not following this user.")
        return redirect(url_for(".user", username=username))
    current_user.unfollow(user)
    db.session.commit()
    current_app.logger.info(f"{current_user.email} unfollowed {user.email}")
    flash("You are not following %s anymore." % username)
    return redirect(url_for(".user", username=username))


@main.route("/followers/<username>")
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash("Invalid user.")
        return redirect(url_for(".index"))
    page = request.args.get("page", 1, type=int)
    pagination = user.followers.paginate(
        page=page, per_page=current_app.config["BLOGG_FOLLOWERS_PER_PAGE"], error_out=False
    )
    follows = [{"user": item.follower, "timestamp": item.timestamp} for item in pagination.items]
    return render_template(
        "followers.html",
        user=user,
        title="Followers of",
        endpoint=".followers",
        pagination=pagination,
        follows=follows,
    )


@main.route("/all")
@login_required
def show_all():
    resp = make_response(redirect(url_for(".index")))
    resp.set_cookie("show_followed", "", max_age=30 * 24 * 60 * 60)
    return resp


@main.route("/followed")
@login_required
def show_followed():
    resp = make_response(redirect(url_for(".index")))
    resp.set_cookie("show_followed", "1", max_age=30 * 24 * 60 * 60)
    return resp


@main.route("/moderate")
@login_required
@permission_required(Permission.MODERATE)
def moderate():
    page = request.args.get("page", 1, type=int)
    pagination = (
        Comment.query.options(joinedload(Comment.author), joinedload(Comment.post))
        .order_by(Comment.timestamp.desc())
        .paginate(
            page=page, per_page=current_app.config["BLOGG_COMMENTS_PER_PAGE"], error_out=False
        )
    )
    comments = pagination.items
    return render_template("moderate.html", comments=comments, pagination=pagination, page=page)


@main.route("/moderate/enable/<int:id>", methods=["POST"])
@login_required
@permission_required(Permission.MODERATE)
def moderate_enable(id):
    comment = db.get_or_404(Comment, id)
    comment.disabled = False
    db.session.commit()
    page = request.values.get("page", 1, type=int)
    return redirect(url_for(".moderate", page=page))


@main.route("/moderate/disable/<int:id>", methods=["POST"])
@login_required
@permission_required(Permission.MODERATE)
def moderate_disable(id):
    comment = db.get_or_404(Comment, id)
    comment.disabled = True
    db.session.commit()
    page = request.values.get("page", 1, type=int)
    return redirect(url_for(".moderate", page=page))


@main.route("/like/<int:id>", methods=["POST"])
@login_required
def like_post(id):
    post = db.get_or_404(Post, id)
    if current_user.has_liked_post(post):
        current_user.unlike_post(post)
        liked = False
    else:
        current_user.like_post(post)
        liked = True
    db.session.commit()

    if request.is_json or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return {"liked": liked, "likes_count": post.likes.count()}

    flash("Liked post!" if liked else "Unliked post.")
    next_url = request.referrer
    if not next_url or not is_safe_redirect_url(next_url):
        next_url = url_for(".index")
    return redirect(next_url)


@main.route("/search")
def search():
    query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    posts = []
    users = []
    pagination = None
    if query:
        post_query = (
            Post.query.options(joinedload(Post.author))
            .filter(Post.body.ilike(f"%{query}%"))
            .order_by(Post.timestamp.desc())
        )
        pagination = post_query.paginate(
            page=page, per_page=current_app.config["BLOGG_POSTS_PER_PAGE"], error_out=False
        )
        posts = pagination.items
        users = (
            User.query.filter((User.username.ilike(f"%{query}%")) | (User.name.ilike(f"%{query}%")))
            .limit(10)
            .all()
        )

    return render_template(
        "search.html", query=query, posts=posts, users=users, pagination=pagination
    )


@main.route("/favicon.ico")
def favicon():
    return current_app.send_static_file("favicon.svg")
