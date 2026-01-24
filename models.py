from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSON

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # Integration flags
    google_connected = db.Column(db.Boolean, nullable=False, default=False)
    # whatsapp_connected = db.Column(db.Boolean, nullable=False, default=False)

    # Google OAuth tokens (per user)
    google_access_token = db.Column(db.Text, nullable=True)
    google_refresh_token = db.Column(db.Text, nullable=True)
    google_token_expiry = db.Column(db.DateTime, nullable=True)
    google_scope = db.Column(db.Text, nullable=True)

    # New fields for per‑user WhatsApp Business Cloud API
    # whatsapp_phone_number_id = db.Column(db.String(64), nullable=True)
    # whatsapp_access_token = db.Column(db.String(512), nullable=True)

    events = db.relationship("Event", back_populates="owner", cascade="all, delete")

    reset_token = db.Column(db.String(128), nullable=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)

    # inside User model class, near theme_color
    theme_color = db.Column(db.String(20), nullable=True)
    font_color = db.Column(db.String(20), nullable=True)
    notifications = db.Column(JSON, nullable=True)


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)

    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # birthday / wedding / engagement / other_individual / other_couple
    event_type = db.Column(db.String(20), nullable=False)

    name1 = db.Column(db.String(255), nullable=False)
    name2 = db.Column(db.String(255), nullable=True)

    # Phone numbers (E.164 format, e.g. +9198...)
    # phone1 = db.Column(db.String(30), nullable=True)
    # phone2 = db.Column(db.String(30), nullable=True)

    base_date = db.Column(db.Date, nullable=False)

    # IANA timezone, e.g., "Asia/Kolkata"
    timezone = db.Column(db.String(64), nullable=False)

    # Time of day to send message (HH:MM)
    send_time = db.Column(db.String(5), nullable=False, default="00:00")

    # Default or custom message
    # message = db.Column(db.Text, nullable=True)

    # Optional custom title for "other_*"
    title = db.Column(db.String(255), nullable=True)

    # Flags
    # send_whatsapp = db.Column(db.Boolean, default=True)
    create_calendar = db.Column(db.Boolean, default=True)

    # Milestone linkage
    google_calendar_event_id = db.Column(db.String(128), nullable=True)
    milestone_source_id = db.Column(db.Integer, db.ForeignKey("events.id"), nullable=True)
    milestone_offset_days = db.Column(db.Integer, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    owner = db.relationship("User", back_populates="events")

    # last_whatsapp_sent_at = db.Column(db.DateTime, nullable=True)

    # Self‑referential relationship: base -> milestones
    milestone_children = db.relationship(
        "Event",
        backref=db.backref("milestone_parent", remote_side=[id]),
        cascade="all, delete-orphan",
    )

    notifications = db.Column(JSON, nullable=True)
