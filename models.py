from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    scans = db.relationship("Scan", backref="owner", lazy="dynamic", cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    target_ip = db.Column(db.String(45), nullable=False)
    start_port = db.Column(db.Integer, nullable=False)
    end_port = db.Column(db.Integer, nullable=False)
    open_count = db.Column(db.Integer, default=0, nullable=False)
    closed_count = db.Column(db.Integer, default=0, nullable=False)
    duration_ms = db.Column(db.Integer, default=0, nullable=False)
    status = db.Column(db.String(20), default="completed", nullable=False)
    results_json = db.Column(db.Text, default="[]", nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
