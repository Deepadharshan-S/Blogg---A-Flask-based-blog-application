from flask import Blueprint

api = Blueprint("api", __name__)

from . import admin, authentication, errors, posts, tokens, users
