from contextlib import contextmanager
from flask_bcrypt import generate_password_hash, check_password_hash
from . import db
from flask import current_app
from flask_login import UserMixin
from uuid import uuid4
from datetime import datetime
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer


def get_uuid():
    return uuid4().hex


class User(UserMixin, db.Model):
    __tablename__ = "user"
    user_uid = db.Column(db.String, primary_key=True, default=get_uuid)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True, index=True)
    hashed_password = db.Column("password", db.String, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=False)
    confirmed = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated = db.Column(
        db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    def get_id(self):
        return self.user_uid

    @property
    def password(self):
        raise AttributeError("user password can't be read")

    @password.setter
    def password(self, password):
        self.hashed_password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.hashed_password, password)

    def confirmation_token(self):
        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        return serializer.dumps({"confirm": self.user_uid})

    def confirm_token(self, token):
        serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
        confirmation_link_timeout = current_app.config.get("CONFIRMATION_LINK_TIMEOUT")
        timeout = confirmation_link_timeout * 60 * 1000
        try:
            data = serializer.loads(token, max_age=timeout)
            if data.get("confirm") != self.user_uid:
                return False
            self.confirmed = True
            db.session.add(self)
            return True
        except (SignatureExpired, BadSignature):
            return False

    def __repr__(self):
        return f"""user_uid: {self.user_uid}
        name: {self.first_name} {self.last_name}
        email: {self.email}
        confirmed: {self.confirmed}
        active: {'True' if self.active else 'False'}
        """