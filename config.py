import os
import os.path

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Change this in production: set SECRET_KEY env var in Render
    SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_ME_TO_A_RANDOM_SECRET")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'milestones.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    JWT_ALGORITHM = "HS256"
    JWT_EXPIRE_MINUTES = 60 * 24 * 365  # 1 Year

    # Google OAuth client (same for all users; identifies your app)
    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = os.environ.get(
        "GOOGLE_REDIRECT_URI",
        "http://localhost:5123/google/callback",
    )
    # Full calendar scope so you can create events
    GOOGLE_SCOPES = ["https://www.googleapis.com/auth/calendar.events"]

    SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
    SENDGRID_FROM_EMAIL = os.environ.get("SENDGRID_FROM_EMAIL", "no-reply@milestoneapp.com")
