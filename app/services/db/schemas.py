import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    ForeignKey,
    Boolean,
    Enum as SQLEnum,
    text,
)
from sqlalchemy.sql import expression
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Users(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    google_sub = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=True)
    picture = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    need_to_refresh_google_api_token = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default=expression.false(),
    )
    test_user = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default=expression.false(),
    )
    birth_date = Column(
        DateTime,
        nullable=False,
        default=lambda: datetime(2000, 1, 1, tzinfo=timezone.utc),
        server_default=text("'2000-01-01 00:00:00+00'"),
    )
    gender = Column(
        String, nullable=False, default="male", server_default=text("'male'")
    )

    google_fitness_api_access_token = relationship(
        "GoogleFitnessAPIAccessTokens",
        back_populates="user",
        uselist=False,
        lazy="joined",
        cascade="all, delete-orphan",
    )
    google_fitness_api_refresh_token = relationship(
        "GoogleFitnessAPIRefreshTokens",
        back_populates="user",
        uselist=False,
        lazy="joined",
        cascade="all, delete-orphan",
    )

    integrations = relationship(
        "UserIntegrations",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class GoogleFitnessAPIAccessTokens(Base):
    __tablename__ = "google_fitness_api_access_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    token = Column(String, nullable=False)

    user = relationship("Users", back_populates="google_fitness_api_access_token")


class GoogleFitnessAPIRefreshTokens(Base):
    __tablename__ = "google_fitness_api_refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        index=True,
        nullable=False,
    )
    token = Column(String, nullable=False)

    user = relationship("Users", back_populates="google_fitness_api_refresh_token")


class IntegrationSource(enum.Enum):
    google_fitness_api = "google_fitness_api"
    google_health_api = "google_health_api"


class UserIntegrations(Base):
    __tablename__ = "user_integrations"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source = Column(
        SQLEnum(IntegrationSource, name="integration_source"),
        nullable=False,
    )
    connected_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("Users", back_populates="integrations")
