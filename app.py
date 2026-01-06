from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlencode

import pytz
import requests
from flask import (
    Flask,
    jsonify,
    request,
    g,
    render_template,
    redirect,
    url_for,
)
from flask_cors import CORS
from flask_migrate import Migrate
from werkzeug.exceptions import Unauthorized, BadRequest, NotFound
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

from config import Config
from models import db, User, Event
from schemas import event_to_dto
from auth_utils import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
)
from timezones import TIMEZONES
from sqlalchemy import and_

import os
from secrets import token_urlsafe




# ---------- Events helpers ----------

def parse_hhmm(send_time: str) -> tuple[int, int]:
    send_time = (send_time or "").strip()
    if len(send_time) != 5 or send_time[2] != ":":
        raise BadRequest("send_time must be in HH:MM format")
    hh = send_time[:2]
    mm = send_time[3:]
    if not (hh.isdigit() and mm.isdigit()):
        raise BadRequest("send_time must be in HH:MM format")
    hour = int(hh)
    minute = int(mm)
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise BadRequest("send_time must be a valid time")
    return hour, minute

def build_calendar_times(base_date, timezone_val: str, send_time: str):
    hour, minute = parse_hhmm(send_time)
    tz = pytz.timezone(timezone_val)

    # Compute next occurrence: same month/day in this year, or next year if already passed.
    today = datetime.now(tz).date()
    year = today.year
    try:
        next_date = datetime(year, base_date.month, base_date.day).date()
    except ValueError:
        # Skip invalid dates like Feb 29 on non-leap year by rolling to next valid year
        next_date = datetime(year + 1, base_date.month, base_date.day).date()

    if next_date < today:
        # Move to next year if this year's date is already in the past
        next_date = datetime(year + 1, base_date.month, base_date.day).date()

    start_dt = tz.localize(
        datetime(next_date.year, next_date.month, next_date.day, hour, minute)
    )
    end_dt = start_dt + timedelta(hours=1)
    return start_dt, end_dt

def send_reset_email(user: User):
    print("DEBUG SENDGRID_API_KEY:", repr(Config.SENDGRID_API_KEY))
    print("DEBUG SENDGRID_FROM_EMAIL:", repr(Config.SENDGRID_FROM_EMAIL))

    if not Config.SENDGRID_API_KEY or not Config.SENDGRID_FROM_EMAIL:
        raise RuntimeError("SendGrid not configured")

    # Generate token valid for 1 hour
    token = token_urlsafe(32)
    user.reset_token = token
    user.reset_token_expires_at = datetime.utcnow() + timedelta(hours=1)
    db.session.commit()

    reset_url = url_for("reset_password_page", token=token, _external=True)

    subject = "Reset your Milestone Events password"
    content = (
        f"Hi,\n\n"
        f"We received a request to reset your password.\n\n"
        f"Click this link to set a new password:\n\n{reset_url}\n\n"
        f"If you did not request this, you can ignore this email.\n"
    )

    payload = {
        "personalizations": [{"to": [{"email": user.email}]}],
        "from": {"email": Config.SENDGRID_FROM_EMAIL},
        "subject": subject,
        "content": [{"type": "text/plain", "value": content}],
    }

    resp = requests.post(
        "https://api.sendgrid.com/v3/mail/send",
        headers={
            "Authorization": f"Bearer {Config.SENDGRID_API_KEY}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=10,
    )
    print("SENDGRID STATUS:", resp.status_code)
    print("SENDGRID BODY:", resp.text)

    if resp.status_code >= 400:
        raise RuntimeError(f"SendGrid error: {resp.text}")




# def send_whatsapp_message(user: User, to_phone: str, body: str) -> dict:
#     """
#     Send a plain text WhatsApp message using this user's WhatsApp Business Cloud API.
#     """
#     phone_number_id = user.whatsapp_phone_number_id
#     access_token = user.whatsapp_access_token

#     if not (phone_number_id and access_token and user.whatsapp_connected):
#         raise RuntimeError("User WhatsApp not connected")

#     url = f"https://graph.facebook.com/v21.0/{phone_number_id}/messages"
#     headers = {
#         "Authorization": f"Bearer {access_token}",
#         "Content-Type": "application/json",
#     }
#     payload = {
#         "messaging_product": "whatsapp",
#         "recipient_type": "individual",
#         "to": to_phone,  # E.164, e.g. 14165551234
#         "type": "text",
#         "text": {
#             "preview_url": False,
#             "body": body,
#         },
#     }

#     resp = requests.post(url, headers=headers, json=payload, timeout=10)
#     return resp.json()



def create_google_calendar_event(user: User, evt: Event):
    if not evt.create_calendar:
        return

    creds = get_google_credentials(user)
    if not creds:
        return

    service = build("calendar", "v3", credentials=creds)

    # Use actual base_date for milestones, recurring logic for base events
    if evt.milestone_source_id is None:
        # Base event – existing behavior
        start_dt, end_dt = build_calendar_times(evt.base_date, evt.timezone, evt.send_time)
    else:
        # Milestone – use the stored absolute date
        hour, minute = parse_hhmm_send_time(evt.send_time)
        tz = pytz.timezone(evt.timezone)
        start_dt = tz.localize(datetime(evt.base_date.year, evt.base_date.month, evt.base_date.day, hour, minute))
        end_dt = start_dt + timedelta(hours=1)

    summary = build_calendar_title(evt)
    body = {
        "summary": summary,
        "start": {"dateTime": start_dt.isoformat(), "timeZone": evt.timezone},
        "end": {"dateTime": end_dt.isoformat(), "timeZone": evt.timezone},
    }
    if evt.milestone_source_id is None:
        body["recurrence"] = ["RRULE:FREQ=YEARLY"]

    created = service.events().insert(calendarId="primary", body=body).execute()
    evt.google_calendar_event_id = created.get("id")
    db.session.commit()



def update_google_calendar_event(user: User, evt: Event) -> None:
    """Update an existing Google Calendar event if it exists; otherwise create it.

    - Base events: recur yearly, use next occurrence (current/next year).
    - Milestones: one‑shot on the actual stored base_date year.
    """
    if not evt.create_calendar:
        return

    creds = get_google_credentials(user)
    if not creds:
        return

    service = build("calendar", "v3", credentials=creds)

    if evt.milestone_source_id is None:
        # Base event – recurring yearly using next occurrence
        start_dt, end_dt = build_calendar_times(evt.base_date, evt.timezone, evt.send_time)
    else:
        # Milestone – one-shot on the actual stored base_date
        hour, minute = parse_hhmm_send_time(evt.send_time)
        tz = pytz.timezone(evt.timezone)
        start_dt = tz.localize(
            datetime(
                evt.base_date.year,
                evt.base_date.month,
                evt.base_date.day,
                hour,
                minute,
            )
        )
        end_dt = start_dt + timedelta(hours=1)

    summary = build_calendar_title(evt)
    body = {
        "summary": summary,
        "start": {
            "dateTime": start_dt.isoformat(),
            "timeZone": evt.timezone,
        },
        "end": {
            "dateTime": end_dt.isoformat(),
            "timeZone": evt.timezone,
        },
    }

    # Base events recur yearly; milestones are one‑shot
    if evt.milestone_source_id is None:
        body["recurrence"] = ["RRULE:FREQ=YEARLY"]

    if evt.google_calendar_event_id:
        # Update existing event
        updated = (
            service.events()
            .update(
                calendarId="primary",
                eventId=evt.google_calendar_event_id,
                body=body,
            )
            .execute()
        )
        evt.google_calendar_event_id = updated.get("id")
    else:
        # No existing event – create a new one
        created = (
            service.events()
            .insert(calendarId="primary", body=body)
            .execute()
        )
        evt.google_calendar_event_id = created.get("id")

    db.session.commit()



def delete_google_calendar_event(user: User, evt: Event):
    if not evt.google_calendar_event_id:
        return
    creds = get_google_credentials(user)
    if not creds:
        return
    service = build("calendar", "v3", credentials=creds)
    try:
        service.events().delete(
            calendarId="primary", eventId=evt.google_calendar_event_id
        ).execute()
    except Exception:
        pass
    evt.google_calendar_event_id = None
    # db.session.commit()


# ---------- Helper ----------

def require_user() -> User:
    user: Optional[User] = getattr(g, "current_user", None)
    if not user:
        raise Unauthorized("Authentication required")
    return user

def build_google_auth_url(state: str) -> str:
    params = {
        "client_id": Config.GOOGLE_CLIENT_ID,
        "redirect_uri": Config.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(Config.GOOGLE_SCOPES),
        "access_type": "offline",
        "include_granted_scopes": "true",
        "state": state,
        "prompt": "consent",
    }
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)

def get_google_credentials(user: User) -> Optional[Credentials]:
    if not user.google_refresh_token:
        return None
    creds_data = {
        "token": user.google_access_token,
        "refresh_token": user.google_refresh_token,
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": Config.GOOGLE_CLIENT_ID,
        "client_secret": Config.GOOGLE_CLIENT_SECRET,
        "scopes": Config.GOOGLE_SCOPES,
    }
    creds = Credentials.from_authorized_user_info(creds_data)
    if not creds.valid and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        user.google_access_token = creds.token
        user.google_token_expiry = datetime.now(timezone.utc) + timedelta(
            seconds=3600
        )
        db.session.commit()
    return creds

def build_calendar_title(evt: Event) -> str:
    etype = evt.event_type
    name1 = (evt.name1 or "").strip()
    name2 = (evt.name2 or "").strip() if evt.name2 else ""
    offset = evt.milestone_offset_days
    is_milestone = offset is not None
    custom_title = (evt.title or "").strip() if hasattr(evt, "title") and evt.title else ""

    couple_name = f"{name1} & {name2}" if name2 else name1

    # BASE EVENTS (no milestone_offset_days)
    if not is_milestone:
        if etype == "birthday":
            return f"{name1}'s Birthday"
        elif etype == "wedding":
            return f"{couple_name}'s Wedding Anniversary"
        elif etype == "engagement":
            return f"{couple_name}'s Engagement Anniversary"
        elif etype == "other_individual":
            return f"{name1}'s {custom_title}" if custom_title else name1
        elif etype == "other_couple":
            return f"{couple_name}'s {custom_title}" if custom_title else couple_name
        return name1 or "Event"

    # MILESTONE EVENTS
    if etype == "birthday":
        # name1 already "Name - <offset> days"
        return name1

    elif etype == "wedding":
        # current style you like: "Name1 & Name2 - X days (Wedding)"
        return f"{name1} (Wedding)"

    elif etype == "engagement":
        # "Name1 & Name2 - X days (Engagement)"
        return f"{name1} (Engagement)"

    elif etype == "other_individual":
        # Want: "Name - <offset> days (Title)"
        print("\n\n\n\nCustom Title: ", custom_title)
        if custom_title and offset is not None:
            return f"{name1} ({custom_title})"
        return name1

    elif etype == "other_couple":
        # Want: "Name1 & Name2 - <offset> days (Title)"
        if custom_title and offset is not None:
            return f"{name1} ({custom_title})"
        return name1

    return name1 or "Event"



def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    Migrate(app, db)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    @app.context_processor
    def inject_timezones():
        return {"TIMEZONES": TIMEZONES}

    # ---------- Auth / user loading ----------

    @app.before_request
    def load_current_user():
        if request.path.startswith("/auth/"):
            if request.path.endswith("/register") or request.path.endswith("/login"):
                g.current_user = None
                return

        # Only protect /api/* here, not /google/*
        if request.path.startswith("/api/"):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                g.current_user = None
                raise Unauthorized("Missing or invalid Authorization header")
            token = auth_header.split(" ", 1)[1]
            user_id = decode_access_token(token)
            if user_id is None:
                raise Unauthorized("Invalid or expired token")
            user = User.query.get(user_id)
            if not user:
                raise Unauthorized("User not found")
            g.current_user = user

    @app.errorhandler(BadRequest)
    def handle_bad_request(e):
        return jsonify({"detail": str(e)}), 400

    @app.errorhandler(Unauthorized)
    def handle_unauthorized(e):
        return jsonify({"detail": str(e)}), 401

    @app.errorhandler(NotFound)
    def handle_not_found(e):
        return jsonify({"detail": "Not found"}), 404

    # ---------- UI pages ----------

    @app.route("/", methods=["GET"])
    def home():
        return redirect(url_for("login_page"))

    @app.route("/login", methods=["GET"])
    def login_page():
        return render_template("login.html")

    @app.route("/register", methods=["GET"])
    def register_page():
        return render_template("register.html")

    @app.route("/events", methods=["GET"])
    def events_page():
        return render_template("events.html")

    @app.route("/events/all", methods=["GET"])
    def events_all_page():
        return render_template("events_all.html")

    @app.route("/events/<int:event_id>", methods=["GET"])
    def event_view_page(event_id: int):
        return render_template("event_view.html", event_id=event_id)

    @app.route("/events/<int:event_id>/edit", methods=["GET"])
    def event_edit_page(event_id: int):
        return render_template("event_edit.html", event_id=event_id)

    @app.route("/change-password", methods=["GET"])
    def change_password_page():
        return render_template("change_password.html")

    # ---------- Auth API ----------

    @app.route("/auth/register", methods=["POST"])
    def register():
        data = request.get_json(force=True)
        email = data.get("email")
        password = data.get("password")
        if not email or not password:
            raise BadRequest("email and password are required")
        if len(password.encode("utf-8")) > 72:
            raise BadRequest("Password too long; must be at most 72 bytes.")
        existing = User.query.filter_by(email=email).first()
        if existing:
            raise BadRequest("Email already registered")
        user = User(
            email=email,
            password_hash=hash_password(password),
            google_connected=False,
            # whatsapp_connected=False,
        )
        db.session.add(user)
        db.session.commit()
        return jsonify({"id": user.id, "email": user.email})

    @app.route("/auth/login", methods=["POST"])
    def login():
        data = request.get_json(force=True)
        email = data.get("email")
        password = data.get("password")
        if not email or not password:
            raise BadRequest("email and password are required")
        user: Optional[User] = User.query.filter_by(email=email).first()
        if not user or not verify_password(password, user.password_hash):
            raise Unauthorized("Invalid email or password")
        token = create_access_token(user.id)
        return jsonify({"access_token": token, "token_type": "bearer"})

    @app.route("/auth/change-password", methods=["POST"])
    def change_password():
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise Unauthorized("Missing or invalid Authorization header")
        token = auth_header.split(" ", 1)[1]
        user_id = decode_access_token(token)
        if user_id is None:
            raise Unauthorized("Invalid or expired token")
        user = User.query.get(user_id)
        if not user:
            raise Unauthorized("User not found")
        data = request.get_json(force=True)
        current_password = data.get("current_password")
        new_password = data.get("new_password")
        if not current_password or not new_password:
            raise BadRequest("current_password and new_password are required")
        if not verify_password(current_password, user.password_hash):
            raise Unauthorized("Current password is incorrect")
        if len(new_password.encode("utf-8")) > 72:
            raise BadRequest("Password too long; must be at most 72 bytes.")
        user.password_hash = hash_password(new_password)
        db.session.commit()
        return jsonify({"detail": "Password updated"})



    # ---------- Google OAuth ----------

    @app.route("/api/me", methods=["GET"])
    def me():
        user = require_user()
        return jsonify(
            {
                "id": user.id,
                "email": user.email,
                "theme_color": getattr(user, "theme_color", None),
            }
        )

    @app.route("/google/login", methods=["GET"])
    def google_login():
        user_id = request.args.get("user_id", type=int)
        if not user_id:
            return "Missing user_id", 400
        state = str(user_id)
        auth_url = build_google_auth_url(state)
        return redirect(auth_url)

    @app.route("/google/callback", methods=["GET"])
    def google_callback():
        code = request.args.get("code")
        state = request.args.get("state")
        if not code or not state:
            return "Missing code/state", 400
        user = User.query.get(int(state))
        if not user:
            return "Unknown user", 400

        token_endpoint = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": Config.GOOGLE_CLIENT_ID,
            "client_secret": Config.GOOGLE_CLIENT_SECRET,
            "redirect_uri": Config.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        resp = requests.post(token_endpoint, data=data)
        if resp.status_code != 200:
            return f"Token exchange failed: {resp.text}", 400
        token_data = resp.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in")
        scope = token_data.get("scope", "")
        user.google_access_token = access_token
        if refresh_token:
            user.google_refresh_token = refresh_token
        user.google_scope = scope
        if expires_in:
            user.google_token_expiry = datetime.now(timezone.utc) + timedelta(
                seconds=int(expires_in)
            )
        user.google_connected = bool(user.google_refresh_token)
        db.session.commit()
        return redirect(url_for("events_page"))

    # ---------- Integrations API ----------

    @app.route("/api/integrations/status", methods=["GET"])
    def integrations_status():
        user = require_user()
        return jsonify(
            {
                "google_connected": bool(user.google_refresh_token),
                # "whatsapp_connected": bool(user.whatsapp_connected),
            }
        )

    @app.route("/api/integrations/google/disconnect", methods=["POST"])
    def api_google_disconnect():
        user = require_user()
        user.google_access_token = None
        user.google_refresh_token = None
        user.google_token_expiry = None
        user.google_scope = None
        user.google_connected = False
        db.session.commit()
        return jsonify({"google_connected": False})

    # @app.route("/whatsapp/connect", methods=["GET"])
    # def whatsapp_connect_page():
    #     return render_template("whatsapp_connect.html")

    # @app.route("/api/integrations/whatsapp/connect", methods=["POST"])
    # def api_whatsapp_connect():
    #     user = require_user()
    #     data = request.get_json(force=True) or {}

    #     phone_number_id = (data.get("phone_number_id") or "").strip()
    #     access_token = (data.get("access_token") or "").strip()

    #     if not phone_number_id or not access_token:
    #         raise BadRequest("phone_number_id and access_token are required")

    #     # Optional: basic validation by calling the WhatsApp Cloud API 'health' endpoint
    #     url = f"https://graph.facebook.com/v21.0/{phone_number_id}/messages"
    #     headers = {
    #         "Authorization": f"Bearer {access_token}",
    #         "Content-Type": "application/json",
    #     }
    #     # Minimal dry‑run: just check auth error vs 200/400 range
    #     test_payload = {
    #         "messaging_product": "whatsapp",
    #         "to": "123",  # invalid on purpose; we just care that token works/authenticates
    #         "type": "text",
    #         "text": {"body": "test"},
    #     }
    #     resp = requests.post(url, headers=headers, json=test_payload, timeout=5)
    #     if resp.status_code == 401 or resp.status_code == 403:
    #         raise BadRequest("Invalid WhatsApp access token or phone_number_id")

    #     # Save credentials
    #     user.whatsapp_phone_number_id = phone_number_id
    #     user.whatsapp_access_token = access_token
    #     user.whatsapp_connected = True
    #     db.session.commit()

    #     return jsonify({"whatsapp_connected": True})


    # @app.route("/api/integrations/whatsapp/disconnect", methods=["POST"])
    # def api_whatsapp_disconnect():
    #     user = require_user()
    #     user.whatsapp_connected = False
    #     user.whatsapp_phone_number_id = None
    #     user.whatsapp_access_token = None
    #     db.session.commit()
    #     return jsonify({"whatsapp_connected": False})

    # ---------- Events API ----------

    @app.route("/api/events/upcoming", methods=["GET"])
    def upcoming_events():
        user = require_user()
        today = datetime.utcnow().date()
        cutoff = today + timedelta(days=60)

        events = (
            Event.query.filter(Event.owner_id == user.id)
            .order_by(Event.base_date.asc())
            .all()
        )

        upcoming = []
        for e in events:
            if e.milestone_source_id is None:
                year = today.year
                try:
                    next_date = datetime(year, e.base_date.month, e.base_date.day).date()
                except ValueError:
                    continue
                if next_date < today:
                    next_date = datetime(
                        year + 1, e.base_date.month, e.base_date.day
                    ).date()
            else:
                next_date = e.base_date

            if today <= next_date <= cutoff:
                dto = event_to_dto(e).__dict__
                dto["next_occurrence"] = next_date.strftime("%Y-%m-%d")
                upcoming.append(dto)

        upcoming.sort(
            key=lambda x: datetime.strptime(x["next_occurrence"], "%Y-%m-%d").date()
        )
        return jsonify(upcoming)

    @app.route("/api/events", methods=["GET"])
    def all_events():
        user = require_user()
        events = (
            Event.query.filter(
                Event.owner_id == user.id,
                Event.milestone_source_id.is_(None),
            )
            .order_by(Event.base_date.asc())
            .all()
        )
        return jsonify([event_to_dto(e).__dict__ for e in events])

    @app.route("/api/events/<int:event_id>", methods=["GET"])
    def get_event(event_id: int):
        user = require_user()
        evt = Event.query.filter_by(id=event_id, owner_id=user.id).first()
        if not evt:
            raise NotFound()

        base_evt = evt.milestone_parent or evt
        milestones = (
            Event.query.filter_by(owner_id=user.id, milestone_source_id=base_evt.id)
            .order_by(Event.base_date.asc())
            .all()
        )

        base_dto = event_to_dto(base_evt).__dict__
        base_dto["milestones"] = [event_to_dto(m).__dict__ for m in milestones]
        base_dto["requested_event_id"] = evt.id
        base_dto["create_milestones"] = len(milestones) > 0
        base_dto["milestone_days"] = [
            m.milestone_offset_days
            for m in milestones
            if m.milestone_offset_days is not None
        ]
        return jsonify(base_dto)

    @app.route("/api/events", methods=["POST"])
    def create_event():
        user = require_user()
        data = request.get_json(force=True)
        event_type = data.get("event_type")
        name1 = data.get("name1")
        name2 = data.get("name2")
        # phone1 = data.get("phone1")
        # phone2 = data.get("phone2")
        base_date_str = data.get("base_date")
        timezone_val = data.get("timezone")
        send_time = data.get("send_time", "00:00")
        raw_message = data.get("message")
        # send_whatsapp = bool(data.get("send_whatsapp", False))
        create_calendar = bool(data.get("create_calendar", False))
        create_milestones = bool(data.get("create_milestones", False))
        milestone_days = data.get("milestone_days") or []
        title = data.get("title")

        valid_types = (
            "birthday",
            "wedding",
            "engagement",
            "other_individual",
            "other_couple",
        )
        if event_type not in valid_types:
            raise BadRequest(
                "event_type must be one of: "
                "birthday, wedding, engagement, other_individual, other_couple"
            )

        # Title mandatory for Other types
        if event_type in ("other_individual", "other_couple"):
            if not (title or "").strip():
                raise BadRequest("title is required for Other event types")

        if not name1 or not base_date_str or not timezone_val:
            raise BadRequest("name1, base_date, timezone are required")

        couple_types = ("wedding", "engagement", "other_couple")
        individual_types = ("birthday", "other_individual")

        # if send_whatsapp:
        #     if event_type in individual_types and not phone1:
        #         raise BadRequest(
        #             "phone is required for this event type when send_whatsapp is true"
        #         )
        #     if event_type in couple_types and (not phone1 or not phone2):
        #         raise BadRequest(
        #             "phone1 and phone2 are required for this event type when "
        #             "send_whatsapp is true"
        #         )
        # else:
        #     phone1 = phone1 or ""
        #     phone2 = phone2 or ""

        try:
            base_date = datetime.strptime(base_date_str, "%Y-%m-%d").date()
        except ValueError:
            raise BadRequest("base_date must be in YYYY-MM-DD format")

        parse_hhmm(send_time)

        # message = (raw_message or "").strip()
        # if send_whatsapp and not message:
        #     raise BadRequest("message is required when send_whatsapp is true")
        # if not send_whatsapp:
        #     message = None

        evt = Event(
            owner_id=user.id,
            event_type=event_type,
            name1=name1,
            name2=name2,
            # phone1=phone1,
            # phone2=phone2,
            base_date=base_date,
            timezone=timezone_val,
            send_time=send_time,
            # message=message,
            # send_whatsapp=send_whatsapp,
            create_calendar=create_calendar,
        )
        if hasattr(Event, "title"):
            evt.title = (title or "").strip() if event_type in (
                "other_individual",
                "other_couple",
            ) else None
        db.session.add(evt)
        db.session.flush()

        today = datetime.utcnow().date()
        if create_milestones:
            for offset in milestone_days:
                try:
                    offset_int = int(offset)
                except (TypeError, ValueError):
                    continue
                if offset_int <= 0:
                    continue
                milestone_date = base_date + timedelta(days=offset_int)
                if milestone_date <= today:
                    continue

                if name2:
                    title_name = f"{name1} & {name2}"
                else:
                    title_name = name1
                milestone_name1 = f"{title_name} - {offset_int} days"

                m_evt = Event(
                    owner_id=user.id,
                    event_type=event_type,
                    name1=milestone_name1,
                    name2=None,
                    # phone1=phone1,
                    # phone2=phone2 if phone2 else None,
                    base_date=milestone_date,
                    timezone=timezone_val,
                    send_time=send_time,
                    # message=message,
                    # send_whatsapp=send_whatsapp,
                    create_calendar=create_calendar,
                    milestone_source_id=evt.id,
                    milestone_offset_days=offset_int,
                )
                if hasattr(Event, "title"):
                    m_evt.title = (title or "").strip() if event_type in (
                        "other_individual",
                        "other_couple",
                    ) else None
                db.session.add(m_evt)

        db.session.commit()

        if create_calendar and user.google_refresh_token:
            create_google_calendar_event(user, evt)
            if create_milestones:
                milestones = Event.query.filter_by(
                    owner_id=user.id, milestone_source_id=evt.id
                ).all()
                for m in milestones:
                    create_google_calendar_event(user, m)

        return jsonify(event_to_dto(evt).__dict__), 201

    @app.route("/api/events/<int:event_id>", methods=["PUT"])
    def update_event(event_id: int):
        """
        Edit behavior:
        - Find the base event for this chain (base or milestone).
        - Delete the base event and all its milestones (and their calendar events).
        - Create a brand new base event (and milestones) using the new data.
        - Return the new base event DTO.
        """
        user = require_user()
        evt = Event.query.filter_by(id=event_id, owner_id=user.id).first()
        if not evt:
            raise NotFound()

        data = request.get_json(force=True)

        # Resolve base event for this chain
        base_evt = evt.milestone_parent or evt

        # 1) Delete old chain (base + milestones + calendar events)
        #    This mirrors the DELETE logic.
        if base_evt.milestone_source_id is None:
            # base event: delete its milestones too
            milestones = Event.query.filter_by(
                owner_id=user.id, milestone_source_id=base_evt.id
            ).all()
            # delete calendar for base
            delete_google_calendar_event(user, base_evt)
            # delete calendar + row for each milestone
            for m in milestones:
                delete_google_calendar_event(user, m)
                db.session.delete(m)
            # finally delete base
            db.session.delete(base_evt)
        else:
            # should not normally happen (base_evt is already base),
            # but keep for completeness
            delete_google_calendar_event(user, base_evt)
            db.session.delete(base_evt)

        db.session.commit()  # old chain is gone

        # 2) Create new base event + milestones using same validation as create_event

        event_type = data.get("event_type")
        name1 = data.get("name1")
        name2 = data.get("name2")
        # phone1 = data.get("phone1")
        # phone2 = data.get("phone2")
        base_date_str = data.get("base_date")
        timezone_val = data.get("timezone")
        send_time = data.get("send_time", "00:00")
        # raw_message = data.get("message")
        # send_whatsapp = bool(data.get("send_whatsapp", False))
        create_calendar = bool(data.get("create_calendar", False))
        create_milestones = bool(data.get("create_milestones", False))
        milestone_days = data.get("milestone_days") or []
        title = data.get("title")  # optional, used for "Other" types

        valid_types = (
            "birthday",
            "wedding",
            "engagement",
            "other_individual",
            "other_couple",
        )
        if event_type not in valid_types:
            raise BadRequest(
                "event_type must be one of: "
                "birthday, wedding, engagement, other_individual, other_couple"
            )

        # Title mandatory for Other types
        if event_type in ("other_individual", "other_couple"):
            if not (title or "").strip():
                raise BadRequest("title is required for Other event types")

        if not name1 or not base_date_str or not timezone_val:
            raise BadRequest("name1, base_date, timezone are required")

        couple_types = ("wedding", "engagement", "other_couple")
        individual_types = ("birthday", "other_individual")

        # if send_whatsapp:
        #     if event_type in individual_types and not phone1:
        #         raise BadRequest(
        #             "phone is required for this event type when send_whatsapp is true"
        #         )
        #     if event_type in couple_types and (not phone1 or not phone2):
        #         raise BadRequest(
        #             "phone1 and phone2 are required for this event type when "
        #             "send_whatsapp is true"
        #         )
        # else:
        #     phone1 = phone1 or ""
        #     phone2 = phone2 or ""

        try:
            base_date = datetime.strptime(base_date_str, "%Y-%m-%d").date()
        except ValueError:
            raise BadRequest("base_date must be in YYYY-MM-DD format")

        parse_hhmm(send_time)

        # message = (raw_message or "").strip()
        # if send_whatsapp and not message:
        #     raise BadRequest("message is required when send_whatsapp is true")
        # if not send_whatsapp:
        #     message = None

        # Create new base event
        new_evt = Event(
            owner_id=user.id,
            event_type=event_type,
            name1=name1,
            name2=name2,
            # phone1=phone1,
            # phone2=phone2,
            base_date=base_date,
            timezone=timezone_val,
            send_time=send_time,
            # message=message,
            # send_whatsapp=send_whatsapp,
            create_calendar=create_calendar,
        )

        # store title if you have a column for it; if not, remove this block
        if hasattr(Event, "title"):
            new_evt.title = (title or "").strip() if event_type in (
                "other_individual",
                "other_couple",
            ) else None

        db.session.add(new_evt)
        db.session.flush()  # get new_evt.id

        today = datetime.utcnow().date()

        # Create new milestones if requested
        if create_milestones:
            for offset in milestone_days:
                try:
                    offset_int = int(offset)
                except (TypeError, ValueError):
                    continue
                if offset_int <= 0:
                    continue
                milestone_date = base_date + timedelta(days=offset_int)
                if milestone_date <= today:
                    continue

                if name2:
                    title_name = f"{name1} & {name2}"
                else:
                    title_name = name1
                milestone_name1 = f"{title_name} - {offset_int} days"

                m_evt = Event(
                    owner_id=user.id,
                    event_type=event_type,
                    name1=milestone_name1,
                    name2=None,
                    # phone1=phone1,
                    # phone2=phone2 if phone2 else None,
                    base_date=milestone_date,
                    timezone=timezone_val,
                    send_time=send_time,
                    # message=message,
                    # send_whatsapp=send_whatsapp,
                    create_calendar=create_calendar,
                    milestone_source_id=new_evt.id,
                    milestone_offset_days=offset_int,
                )
                if hasattr(Event, "title"):
                    m_evt.title = (title or "").strip() if event_type in (
                        "other_individual",
                        "other_couple",
                    ) else None
                db.session.add(m_evt)

        db.session.commit()

        # Create Google calendar events for new chain
        if create_calendar and user.google_refresh_token:
            create_google_calendar_event(user, new_evt)
            if create_milestones:
                milestones = Event.query.filter_by(
                    owner_id=user.id, milestone_source_id=new_evt.id
                ).all()
                for m in milestones:
                    create_google_calendar_event(user, m)

        return jsonify(event_to_dto(new_evt).__dict__)

    @app.route("/api/events/<int:event_id>", methods=["DELETE"])
    def delete_event(event_id: int):
        user = require_user()
        evt = Event.query.filter_by(id=event_id, owner_id=user.id).first()
        if not evt:
            raise NotFound()

        # If base event, also delete its milestones and all calendar events
        if evt.milestone_source_id is None:
            milestones = Event.query.filter_by(
                owner_id=user.id, milestone_source_id=evt.id
            ).all()
            delete_google_calendar_event(user, evt)
            for m in milestones:
                delete_google_calendar_event(user, m)
                db.session.delete(m)
            db.session.delete(evt)
        else:
            # Individual milestone
            delete_google_calendar_event(user, evt)
            db.session.delete(evt)

        db.session.commit()
        return jsonify({"detail": "Deleted"})

    @app.route("/auth/forgot-password", methods=["POST"])
    def forgot_password():
        data = request.get_json(force=True) or {}
        email = (data.get("email") or "").strip().lower()
        if not email:
            raise BadRequest("email is required")

        user = User.query.filter_by(email=email).first()
        # Always return 200 to avoid leaking which emails exist
        if not user:
            return jsonify({"detail": "If that email exists, a reset link has been sent."})

        try:
            send_reset_email(user)
        except Exception as e:
            # Log e in real app
            return jsonify({"detail": "Failed to send reset email."}), 500

        return jsonify({"detail": "If that email exists, a reset link has been sent."})

    @app.route("/reset-password", methods=["GET"])
    def reset_password_page():
        token = request.args.get("token", "")
        if not token:
            return "Missing token", 400
        return render_template("reset_password.html", token=token)

    @app.route("/auth/reset-password", methods=["POST"])
    def reset_password():
        data = request.get_json(force=True) or {}
        token = (data.get("token") or "").strip()
        new_password = data.get("new_password") or ""

        if not token or not new_password:
            raise BadRequest("token and new_password are required")

        user = User.query.filter_by(reset_token=token).first()
        if not user:
            raise BadRequest("Invalid or expired reset token")

        if not user.reset_token_expires_at or user.reset_token_expires_at < datetime.utcnow():
            raise BadRequest("Invalid or expired reset token")

        if len(new_password.encode("utf-8")) > 72:
            raise BadRequest("Password too long; must be at most 72 bytes.")

        user.password_hash = hash_password(new_password)
        user.reset_token = None
        user.reset_token_expires_at = None
        db.session.commit()

        return jsonify({"detail": "Password has been reset."})

    @app.route("/api/me", methods=["PUT"])
    def update_me():
        user = require_user()
        data = request.get_json(force=True) or {}

        if "theme_color" in data:
            theme_color = data.get("theme_color")
            if theme_color is None:
                # clear theme to use default on frontend
                user.theme_color = None
            else:
                theme_color = theme_color.strip()
                # very simple validation: "#RRGGBB"
                if not (len(theme_color) == 7 and theme_color.startswith("#")):
                    raise BadRequest("theme_color must be in #RRGGBB format")
                user.theme_color = theme_color
            db.session.commit()

        return jsonify(
            {
                "id": user.id,
                "email": user.email,
                "theme_color": getattr(user, "theme_color", None),
            }
        )


    return app


# def dispatch_due_whatsapp_messages(now_utc: datetime | None = None) -> int:
#     """
#     Find events whose WhatsApp message should be sent now and send them.

#     Returns the count of messages attempted.
#     """
#     if now_utc is None:
#         now_utc = datetime.now(timezone.utc)

#     # Round down to minute but keep tzinfo
#     now_utc = now_utc.replace(second=0, microsecond=0)

#     print("Dispatcher called at", now_utc)

#     users = User.query.filter_by(whatsapp_connected=True).all()
#     sent_count = 0

#     for user in users:
#         events = (
#             Event.query
#             .filter(
#                 Event.owner_id == user.id,
#                 Event.send_whatsapp.is_(True),
#                 Event.phone1 != "",
#                 Event.message.isnot(None),
#                 Event.last_whatsapp_sent_at.is_(None),
#             )
#             .all()
#         )

#         for evt in events:
#             print(
#                 "Candidate evt",
#                 evt.id,
#                 evt.name1,
#                 evt.base_date,
#                 evt.send_time,
#                 evt.timezone,
#                 "milestone_source_id:",
#                 evt.milestone_source_id,
#             )

#             # Compute "today" in the event's timezone
#             tz = pytz.timezone(evt.timezone)
#             now_local = now_utc.astimezone(tz)
#             today_local = now_local.date()

#             # Check if this event should fire today
#             # Base (yearly) events: same month/day each year
#             if evt.milestone_source_id is None:
#                 try:
#                     next_date = datetime(
#                         year=today_local.year,
#                         month=evt.base_date.month,
#                         day=evt.base_date.day,
#                     ).date()
#                 except ValueError:
#                     # Skip invalid dates (e.g. Feb 29 on non-leap year)
#                     continue

#                 if next_date != today_local:
#                     continue
#             else:
#                 # Milestones are one-shot: base_date is the fire date
#                 if evt.base_date != today_local:
#                     continue

#             # Check time match (HH:MM)
#             try:
#                 expected_hour, expected_minute = parse_hhmm(evt.send_time)
#             except BadRequest:
#                 # Skip events with invalid time
#                 continue

#             # Fire when we reach the scheduled minute or later (once),
#             # guarded by last_whatsapp_sent_at
#             if not (
#                 now_local.hour == expected_hour
#                 and now_local.minute >= expected_minute
#             ):
#                 continue

#             # At this point, evt is due -> send WhatsApp
#             try:
#                 send_whatsapp_message(user, evt.phone1, evt.message)
#                 evt.last_whatsapp_sent_at = now_utc  # mark as sent
#                 db.session.add(evt)
#                 sent_count += 1
#             except Exception as e:
#                 # In prod you would log this properly
#                 print(f"Failed to send WhatsApp for event {evt.id}: {e}")

#     db.session.commit()
#     return sent_count

if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5123, debug=True)
