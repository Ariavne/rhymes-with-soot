"""Domain models on the shared Base. create_all runs at startup."""
from sqlalchemy import Column, String, DateTime

from rhymes_with_soot.access import register_access
from rhymes_with_soot.models import Base, uuid4, now

# Declare the accesses this site gates on (the admin's editor offers these).
# Remove the declaration and its gated UI if you do not need them.
register_access("area.feature", label="Feature",
                help="Grants access to the example feature on the dashboard.")


class Note(Base):
    __tablename__ = "notes"

    id = Column(String(36), primary_key=True, default=uuid4)
    body = Column(String(512), nullable=False)
    created_at = Column(DateTime, default=now)
