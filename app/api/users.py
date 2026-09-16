from flask import current_app, jsonify, request, url_for
from sqlalchemy.orm import joinedload

from ..models import Post, User
from . import api
from .errors import not_found


@api.route("/users/<username>", methods=["GET"])
def get_user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        return not_found(f"User {username} not found")
    return jsonify(user.to_json())


@api.route("/users/<username>/posts", methods=["GET"])
def get_user_posts(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        return not_found(f"User {username} not found")

    page = request.args.get("page", 1, type=int)
    per_page = min(
        request.args.get("per_page", current_app.config["BLOGG_POSTS_PER_PAGE"], type=int), 100
    )

    pagination = (
        user.posts.options(joinedload(Post.author))
        .order_by(Post.timestamp.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )
    posts = pagination.items
    prev_url = (
        url_for("api.get_user_posts", username=username, page=page - 1, per_page=per_page)
        if pagination.has_prev
        else None
    )
    next_url = (
        url_for("api.get_user_posts", username=username, page=page + 1, per_page=per_page)
        if pagination.has_next
        else None
    )

    return jsonify(
        {
            "user": user.username,
            "posts": [post.to_json() for post in posts],
            "total": pagination.total,
            "pages": pagination.pages,
            "current_page": page,
            "prev_url": prev_url,
            "next_url": next_url,
        }
    )
