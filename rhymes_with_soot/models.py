"""Single shared Base; each site has its own DB file so tables don't collide."""
import uuid

from sqlalchemy import Column, String, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()


def uuid4():
    return str(uuid.uuid4())


def now():
    from rhymes_with_soot.util import utcnow
    return utcnow()


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=uuid4)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    # Access level: "user" or "admin". Admins manage accounts but cannot
    # view or recover other users' data.
    role = Column(String(16), nullable=False, default="user")
    created_at = Column(DateTime, default=now)
