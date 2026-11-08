"""Domain models on the shared Base. create_all runs at startup."""
from sqlalchemy import Column, String, DateTime

from rhymes_with_soot.models import Base, uuid4, now


class Note(Base):
    __tablename__ = "notes"

    id = Column(String(36), primary_key=True, default=uuid4)
    body = Column(String(512), nullable=False)
    created_at = Column(DateTime, default=now)
