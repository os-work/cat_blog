from logging import getLogger
from flask import render_template, redirect, url_for, request, flash
from . import auth_bp
from ..models import User, db
from .. import login_manager
from .forms import LoginForm
from flask_login import login_user
from urllib.parse import urlparse


logger = getLogger(__name__)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(user_id)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).one_or_none()
        if user is None or not user.verify_password(form.password.data):
            flash("Invalid email or password", "warning")
            return redirect(url_for("auth_bp.login"))

        login_user(user, remember=form.remember_me.data)
        next_url = request.args.get("next")
        if not next_url or urlparse(next_url).netloc != "":
            next_url = url_for("intro_bp.home")
        return redirect(next_url)

    return render_template("login.html", form=form)
