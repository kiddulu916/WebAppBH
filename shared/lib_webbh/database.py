"""Async database engine singleton, session factory, and declarative base."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncIterator, Optional

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.types import JSON
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# ---------------------------------------------------------------------------
# Module-level singletons
# ---------------------------------------------------------------------------
_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


# ---------------------------------------------------------------------------
# URL builder (private)
# ---------------------------------------------------------------------------
def _build_url() -> str:
    """Construct a database URL from environment variables.

    Environment variables
    ---------------------
    DB_DRIVER : str  – SQLAlchemy async driver (default ``postgresql+asyncpg``)
    DB_USER   : str  – database user           (default ``webbh_admin``)
    DB_PASS   : str  – database password        (default ``""``)
    DB_HOST   : str  – database host            (default ``localhost``)
    DB_PORT   : str  – database port            (default ``5432``)
    DB_NAME   : str  – database / file name     (default ``webbh``)
    """
    driver = os.environ.get("DB_DRIVER", "postgresql+asyncpg")
    name = os.environ.get("DB_NAME", "webbh")

    if driver.startswith("sqlite"):
        return f"{driver}:///{name}"

    user = os.environ.get("DB_USER", "webbh_admin")
    password = os.environ.get("DB_PASS", "")
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    return f"{driver}://{user}:{password}@{host}:{port}/{name}"


# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------
def get_engine() -> AsyncEngine:
    """Return the global :class:`AsyncEngine`, creating it on first call."""
    global _engine
    if _engine is None:
        url = _build_url()
        kwargs: dict = {}
        if not url.startswith("sqlite"):
            kwargs.update(
                pool_size=int(os.environ.get("DB_POOL_SIZE", "10")),
                max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "20")),
                pool_recycle=int(os.environ.get("DB_POOL_RECYCLE", "3600")),
                pool_pre_ping=True,
            )
        _engine = create_async_engine(url, **kwargs)
    return _engine


# ---------------------------------------------------------------------------
# Session context manager
# ---------------------------------------------------------------------------
@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    """Yield an :class:`AsyncSession` and close it on exit.

    Usage::

        async with get_session() as session:
            result = await session.execute(...)
    """
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            bind=get_engine(),
            expire_on_commit=False,
        )

    session = _session_factory()
    try:
        yield session
    finally:
        await session.close()


# ---------------------------------------------------------------------------
# Declarative base
# ---------------------------------------------------------------------------
class Base(AsyncAttrs, DeclarativeBase):
    """Project-wide declarative base with async attribute support."""


# ---------------------------------------------------------------------------
# Timestamp mixin
# ---------------------------------------------------------------------------
class TimestampMixin:
    """Mixin that adds ``created_at`` / ``updated_at`` UTC timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        default=func.now(),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=func.now(),
        server_default=func.now(),
        onupdate=func.now(),
    )


# ---------------------------------------------------------------------------
# OAM Models (10 tables)
# ---------------------------------------------------------------------------


class Target(TimestampMixin, Base):
    """Top-level reconnaissance target (company / domain)."""

    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint("company_name", "base_domain", name="uq_targets_company_domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    company_name: Mapped[str] = mapped_column(String(255))
    base_domain: Mapped[str] = mapped_column(String(255))
    target_profile: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    assets: Mapped[list["Asset"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    identities: Mapped[list["Identity"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    cloud_assets: Mapped[list["CloudAsset"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    jobs: Mapped[list["JobState"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    api_schemas: Mapped[list["ApiSchema"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    mobile_apps: Mapped[list["MobileApp"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    snapshots: Mapped[list["AssetSnapshot"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    bounty_submissions: Mapped[list["BountySubmission"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    scheduled_scans: Mapped[list["ScheduledScan"]] = relationship(back_populates="target", cascade="all, delete-orphan")
    scope_violations: Mapped[list["ScopeViolation"]] = relationship(back_populates="target", cascade="all, delete-orphan")


class Asset(TimestampMixin, Base):
    """Discovered asset linked to a target (subdomain, IP, URL, etc.)."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("target_id", "asset_type", "asset_value", name="uq_assets_target_type_value"),
        Index("ix_assets_target_type", "target_id", "asset_type"),
        Index("ix_assets_target_created", "target_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    asset_type: Mapped[str] = mapped_column(String(50))
    asset_value: Mapped[str] = mapped_column(String(500))
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    tech: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="assets")
    locations: Mapped[list["Location"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    observations: Mapped[list["Observation"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    parameters: Mapped[list["Parameter"]] = relationship(back_populates="asset", cascade="all, delete-orphan")
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(back_populates="asset")
    api_schemas: Mapped[list["ApiSchema"]] = relationship(back_populates="asset")
    mobile_apps: Mapped[list["MobileApp"]] = relationship(back_populates="asset")


class Identity(TimestampMixin, Base):
    """WHOIS / ASN identity data associated with a target."""

    __tablename__ = "identities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    asn: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    organization: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    whois_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="identities")


class Location(TimestampMixin, Base):
    """Network location (port / service) observed on an asset."""

    __tablename__ = "locations"
    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_locations_asset_port_proto"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("assets.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    service: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    state: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="locations")


class Observation(TimestampMixin, Base):
    """HTTP / technology observation gathered from an asset."""

    __tablename__ = "observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("assets.id"))
    tech_stack: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    page_title: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    headers: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="observations")


class CloudAsset(TimestampMixin, Base):
    """Cloud resource (S3 bucket, Azure blob, GCP storage, etc.)."""

    __tablename__ = "cloud_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    provider: Mapped[str] = mapped_column(String(20))
    asset_type: Mapped[str] = mapped_column(String(100))
    url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    is_public: Mapped[bool] = mapped_column(Boolean, default=False)
    findings: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="cloud_assets")


class Parameter(TimestampMixin, Base):
    """URL / form parameter discovered on an asset."""

    __tablename__ = "parameters"
    __table_args__ = (
        UniqueConstraint("asset_id", "param_name", name="uq_parameters_asset_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("assets.id"))
    param_name: Mapped[str] = mapped_column(String(255))
    param_value: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="parameters")


class Vulnerability(TimestampMixin, Base):
    """Security vulnerability found against a target / asset."""

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("ix_vulns_target_severity", "target_id", "severity"),
        Index("ix_vulns_target_created", "target_id", "created_at"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    asset_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("assets.id"), nullable=True
    )
    severity: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    poc: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="vulnerabilities")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="vulnerabilities")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="vulnerability")
    bounty_submissions: Mapped[list["BountySubmission"]] = relationship(back_populates="vulnerability")


class JobState(TimestampMixin, Base):
    """Runtime state of a reconnaissance container / job."""

    __tablename__ = "job_state"
    __table_args__ = (
        Index("ix_jobstate_target_status", "target_id", "status"),
        Index("ix_jobstate_container_status", "container_name", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    container_name: Mapped[str] = mapped_column(String(255))
    current_phase: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    status: Mapped[str] = mapped_column(String(20))
    last_seen: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    last_tool_executed: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True
    )

    target: Mapped["Target"] = relationship(back_populates="jobs")


class Alert(TimestampMixin, Base):
    """Notification / alert tied to a target and optionally a vulnerability."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_target_read", "target_id", "is_read"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    vulnerability_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("vulnerabilities.id"), nullable=True
    )
    alert_type: Mapped[str] = mapped_column(String(100))
    message: Mapped[str] = mapped_column(Text)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)

    target: Mapped["Target"] = relationship(back_populates="alerts")
    vulnerability: Mapped[Optional["Vulnerability"]] = relationship(back_populates="alerts")


class ApiSchema(TimestampMixin, Base):
    """Discovered API endpoint (path + method + params) for a target."""

    __tablename__ = "api_schemas"
    __table_args__ = (
        UniqueConstraint(
            "target_id", "asset_id", "method", "path",
            name="uq_api_schemas_target_asset_method_path",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    asset_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("assets.id"), nullable=True
    )
    method: Mapped[str] = mapped_column(String(10))
    path: Mapped[str] = mapped_column(String(2000))
    params: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    auth_required: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    spec_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    target: Mapped["Target"] = relationship(back_populates="api_schemas")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="api_schemas")


class MobileApp(TimestampMixin, Base):
    """Mobile application binary (APK/IPA) linked to a target."""

    __tablename__ = "mobile_apps"
    __table_args__ = (
        UniqueConstraint(
            "target_id", "platform", "package_name",
            name="uq_mobile_apps_target_platform_pkg",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    asset_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("assets.id"), nullable=True
    )
    platform: Mapped[str] = mapped_column(String(10))
    package_name: Mapped[str] = mapped_column(String(500))
    version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    permissions: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    signing_info: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    mobsf_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    decompiled_path: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    source_tool: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    target: Mapped["Target"] = relationship(back_populates="mobile_apps")
    asset: Mapped[Optional["Asset"]] = relationship(back_populates="mobile_apps")


class AssetSnapshot(TimestampMixin, Base):
    """Point-in-time snapshot of all assets for a target (recon diffing)."""

    __tablename__ = "asset_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id", ondelete="CASCADE"))
    scan_number: Mapped[int] = mapped_column(Integer)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    asset_hashes: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="snapshots")

    __table_args__ = (
        UniqueConstraint("target_id", "scan_number", name="uq_snapshot_target_scan"),
    )


class BountySubmission(TimestampMixin, Base):
    """Tracks vulnerability submissions to bug bounty platforms."""

    __tablename__ = "bounty_submissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    vulnerability_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerabilities.id"))
    platform: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50))
    submission_url: Mapped[Optional[str]] = mapped_column(String(2000), nullable=True)
    expected_payout: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    actual_payout: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    target: Mapped["Target"] = relationship(back_populates="bounty_submissions")
    vulnerability: Mapped["Vulnerability"] = relationship(back_populates="bounty_submissions")


class ScheduledScan(TimestampMixin, Base):
    """Cron-based recurring scan configuration."""

    __tablename__ = "scheduled_scans"
    __table_args__ = (
        UniqueConstraint("target_id", "cron_expression", name="uq_scheduled_scans_target_cron"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    cron_expression: Mapped[str] = mapped_column(String(100))
    playbook: Mapped[str] = mapped_column(String(100), default="wide_recon")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    target: Mapped["Target"] = relationship(back_populates="scheduled_scans")


class ScopeViolation(TimestampMixin, Base):
    """Audit log of out-of-scope attempts."""

    __tablename__ = "scope_violations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(Integer, ForeignKey("targets.id"))
    tool_name: Mapped[str] = mapped_column(String(100))
    input_value: Mapped[str] = mapped_column(String(2000))
    violation_type: Mapped[str] = mapped_column(String(50))

    target: Mapped["Target"] = relationship(back_populates="scope_violations")


class CustomPlaybook(TimestampMixin, Base):
    """User-defined playbook configuration."""

    __tablename__ = "custom_playbooks"
    __table_args__ = (
        UniqueConstraint("name", name="uq_custom_playbooks_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100))
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    stages: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    concurrency: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
