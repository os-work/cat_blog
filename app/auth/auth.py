from logging import getLogger
from flask import render_template, redirect, url_for, request, flash
from . import auth_bp
from ..models import User, db
from .. import login_manager
from .forms import LoginForm, RegisterNewUserForm
from flask_login import login_user, logout_user, current_user
from urllib.parse import urlparse


logger = getLogger(__name__)


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("intro_bp.home"))

    form = LoginForm()
    if form.cancel.data:
        return redirect(url_for("intro_bp.home"))
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


@auth_bp.route("/logout")
def logout():
    logout_user()
    flash("You've been logged out", "light")
    return redirect(url_for("intro_bp.home"))


@auth_bp.route("/register_new_user", methods=["GET", "POST"])
def register_new_user():
    if current_user.is_authenticated:
        return redirect(url_for("intro_bp.home"))

    form = RegisterNewUserForm()
    if form.cancel.data:
        return redirect(url_for("intro_bp.home"))
    if form.validate_on_submit():
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            password=form.password.data,
            active=True,
        )
        db.session.add(user)
        db.session.commit()
        logger.debug(f"new user {form.email.data} added")
        return redirect(url_for("auth_bp.login"))

    return render_template("register_new_user.html", form=form)