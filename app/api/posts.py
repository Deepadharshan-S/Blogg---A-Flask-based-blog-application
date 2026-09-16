from flask import current_app, g, jsonify, request, url_for
from sqlalchemy.orm import joinedload

from .. import db
from ..models import Comment, Permission, Post
from . import api
from .authentication import permission_required_api, token_auth_required
from .errors import bad_request, forbidden, not_found


@api.route("/posts", methods=["GET"])
def get_posts():
    page = request.args.get("page", 1, type=int)
    per_page = min(
        request.args.get("per_page", current_app.config["BLOGG_POSTS_PER_PAGE"], type=int), 100
    )

    pagination = (
        Post.query.options(joinedload(Post.author))
        .order_by(Post.timestamp.desc())
        .paginate(page=page, per_page=per_page, error_out=False)
    )
    posts = pagination.items
    prev_url = (
        url_for("api.get_posts", page=page - 1, per_page=per_page) if pagination.has_prev else None
    )
    next_url = (
        url_for("api.get_posts", page=page + 1, per_page=per_page) if pagination.has_next else None
    )

    return jsonify(
        {
            "posts": [post.to_json() for post in posts],
            "total": pagination.total,
            "pages": pagination.pages,
            "current_page": page,
            "prev_url": prev_url,
            "next_url": next_url,
        }
    )


@api.route("/posts/<int:id>", methods=["GET"])
def get_post(id):
    post = Post.query.options(joinedload(Post.author)).filter_by(id=id).first()
    if post is None:
        return not_found(f"Post with id {id} not found")

    comments = (
        post.comments.options(joinedload(Comment.author)).order_by(Comment.timestamp.asc()).all()
    )
    data = post.to_json()
    data["comments"] = [comment.to_json() for comment in comments]
    return jsonify(data)


@api.route("/posts", methods=["POST"])
@token_auth_required
@permission_required_api(Permission.WRITE)
def new_post():
    data = request.get_json() or {}
    body = data.get("body", "").strip()
    if not body:
        return bad_request("Post body cannot be empty.")

    post = Post(body=body, author=g.current_user)
    db.session.add(post)
    db.session.commit()
    response = jsonify(post.to_json())
    response.status_code = 201
    response.headers["Location"] = url_for("api.get_post", id=post.id)
    return response


@api.route("/posts/<int:id>", methods=["PUT"])
@token_auth_required
def edit_post(id):
    post = db.session.get(Post, id)
    if post is None:
        return not_found(f"Post with id {id} not found")

    if g.current_user != post.author and not g.current_user.can(Permission.ADMIN):
        return forbidden("You can only edit your own posts.")

    data = request.get_json() or {}
    body = data.get("body", "").strip()
    if not body:
        return bad_request("Post body cannot be empty.")

    post.body = body
    db.session.add(post)
    db.session.commit()
    return jsonify(post.to_json())


@api.route("/posts/<int:id>/like", methods=["POST"])
@token_auth_required
def api_like_post(id):
    post = db.session.get(Post, id)
    if post is None:
        return not_found(f"Post with id {id} not found")

    if g.current_user.has_liked_post(post):
        g.current_user.unlike_post(post)
        liked = False
    else:
        g.current_user.like_post(post)
        liked = True
    db.session.commit()
    return jsonify({"liked": liked, "likes_count": post.likes.count()})
