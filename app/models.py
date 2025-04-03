from contextlib import contextmanager
from flask_bcrypt import generate_password_hash, check_password_hash
from . import db
from flask_login import UserMixin
from uuid import uuid4
from datetime import datetime


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

    def __repr__(self):
        return f"""user_uid: {self.user_uid}
        name: {self.first_name} {self.last_name}
        email: {self.email}
        active: {'True' if self.active else 'False'}
        """