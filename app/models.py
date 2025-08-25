from typing import Optional, List
from decimal import Decimal
from flask_login import UserMixin
from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
import sqlalchemy as sa
import sqlalchemy.orm as so
import jwt
from flask import current_app
from time import time
from app import db, login
from hashlib import md5

class TimestampMixin:
    """Mixin to add created_at and updated_at timestamps to models."""
    created_at: so.Mapped[datetime] = so.mapped_column(
        sa.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    updated_at: so.Mapped[datetime] = so.mapped_column(
        sa.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )

class User(UserMixin, TimestampMixin, db.Model):
    """Enhanced User model with PentestSaaS functionality."""
    __tablename__ = 'users'

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    username: so.Mapped[str] = so.mapped_column(sa.String(64), unique=True, index=True)
    email: so.Mapped[str] = so.mapped_column(sa.String(120), unique=True, index=True)
    password_hash: so.Mapped[Optional[str]] = so.mapped_column(sa.String(256))
    
    # Additional PentestSaaS fields
    first_name: so.Mapped[Optional[str]] = so.mapped_column(sa.String(100))
    last_name: so.Mapped[Optional[str]] = so.mapped_column(sa.String(100))
    subscription_tier: so.Mapped[str] = so.mapped_column(sa.String(20), default='free')
    is_active: so.Mapped[bool] = so.mapped_column(sa.Boolean, default=True)
    email_verified: so.Mapped[bool] = so.mapped_column(sa.Boolean, default=False)
    last_login: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))

    scans: so.Mapped[List["Scan"]] = so.relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    api_keys: so.Mapped[List["ApiKey"]] = so.relationship("ApiKey", back_populates="user", cascade="all, delete-orphan")
    consent_logs: so.Mapped[List["ConsentLog"]] = so.relationship("ConsentLog", back_populates="user", cascade="all, delete-orphan")
    subscriptions: so.Mapped[List["Subscription"]] = so.relationship("Subscription", back_populates="user", cascade="all, delete-orphan")

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return f'https://www.gravatar.com/avatar/{digest}?d=identicon&s={size}'


    def set_password(self, password: str) -> None:
        """Set the user's password (fixed typo from set_pasword)."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Check the user's password."""
        return check_password_hash(self.password_hash, password)

    @property
    def full_name(self) -> str:
        """Get the user's full name."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.first_name or self.last_name or self.username

    @property
    def display_name(self) -> str:
        """Get display name (username or full name)."""
        return self.full_name if (self.first_name or self.last_name) else self.username
    
    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            current_app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return db.session.get(User, id)


    def __repr__(self) -> str:
        return f'<User {self.username}>'


class Scan(TimestampMixin, db.Model):
    __tablename__ = 'scans'
    
    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('users.id'), nullable=False, index=True)
    target_url: so.Mapped[str] = so.mapped_column(sa.String(2048), nullable=False)
    target_ip: so.Mapped[Optional[str]] = so.mapped_column(sa.String(45))
    scan_type: so.Mapped[str] = so.mapped_column(sa.String(20), nullable=False)
    scan_name: so.Mapped[str] = so.mapped_column(sa.String(200))
    status: so.Mapped[str] = so.mapped_column(sa.String(20), default='queued', index=True)
    celery_task_id: so.Mapped[Optional[str]] = so.mapped_column(sa.String(255))
    started_at: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))
    completed_at: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))
    scan_config: so.Mapped[Optional[str]] = so.mapped_column(sa.Text)  # JSON string for scan parameters
    total_vulnerabilities: so.Mapped[int] = so.mapped_column(sa.Integer, default=0)
    high_severity_count: so.Mapped[int] = so.mapped_column(sa.Integer, default=0)
    medium_severity_count: so.Mapped[int] = so.mapped_column(sa.Integer, default=0)
    low_severity_count: so.Mapped[int] = so.mapped_column(sa.Integer, default=0)

    user: so.Mapped["User"] = so.relationship("User", back_populates="scans")
    tool_results: so.Mapped[List["ToolResult"]] = so.relationship("ToolResult", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities: so.Mapped[List["Vulnerability"]] = so.relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    reports: so.Mapped[List["Report"]] = so.relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    consent_logs: so.Mapped[List["ConsentLog"]] = so.relationship("ConsentLog", back_populates="scan", cascade="all, delete-orphan")



    @property
    def duration(self) -> Optional[float]:
        """Calculate scan duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    @property
    def is_completed(self) -> bool:
        """Check if scan is completed."""
        return self.status in ['completed', 'failed', 'cancelled']

    @property
    def progress_percentage(self) -> int:
        """Calculate scan progress percentage based on status."""
        status_progress = {
            'queued': 0,
            'running': 50,
            'completed': 100,
            'failed': 100,
            'cancelled': 100
        }
        return status_progress.get(self.status, 0)


    def __repr__(self) -> str:
        return f'<Scan {self.id}: {self.target_url} ({self.status})>'
    

class ToolResult(TimestampMixin, db.Model):
    """Model for storing results of individual tools used in scans."""
    __tablename__ = 'tool_results'

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    scan_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('scans.id'), nullable=False, index=True)
    tool_name: so.Mapped[str] = so.mapped_column(sa.String(50), nullable=False)  # nmap, zap, metasploit
    status: so.Mapped[str] = so.mapped_column(sa.String(20), default='pending')  # pending, running, completed, failed
    raw_output: so.Mapped[Optional[str]] = so.mapped_column(sa.Text)  # JSON string of tool output
    started_at: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))
    completed_at: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))
    error_message: so.Mapped[Optional[str]] = so.mapped_column(sa.Text)
    
    scan: so.Mapped["Scan"] = so.relationship("Scan", back_populates="tool_results")
    vulnerabilities: so.Mapped[List["Vulnerability"]] = so.relationship("Vulnerability", back_populates="tool_result")



    @property
    def duration(self) -> Optional[float]:
        """Calculate tool execution duration in seconds."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    def __repr__(self) -> str:
        return f'<ToolResult {self.tool_name} for Scan {self.scan_id} ({self.status})>'
    


class Vulnerability(TimestampMixin, db.Model):
    """Model for storing vulnerabilities found during scans."""
    __tablename__ = 'vulnerabilities'

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    scan_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('scans.id'), nullable=False, index=True)
    tool_result_id: so.Mapped[Optional[int]] = so.mapped_column(sa.ForeignKey('tool_results.id'))
    vuln_type: so.Mapped[str] = so.mapped_column(sa.String(100), nullable=False)  # sql_injection, xss, open_port, etc.
    severity: so.Mapped[str] = so.mapped_column(sa.String(10), nullable=False, index=True)  # critical, high, medium, low, info
    title: so.Mapped[str] = so.mapped_column(sa.String(200), nullable=False)
    description: so.Mapped[Optional[str]] = so.mapped_column(sa.Text)
    affected_url: so.Mapped[Optional[str]] = so.mapped_column(sa.String(500))
    affected_parameter: so.Mapped[Optional[str]] = so.mapped_column(sa.String(100))
    cve_id: so.Mapped[Optional[str]] = so.mapped_column(sa.String(20))
    cvss_score: so.Mapped[Optional[Decimal]] = so.mapped_column(sa.DECIMAL(3, 1))  # 0.0 to 10.0
    remediation: so.Mapped[Optional[str]] = so.mapped_column(sa.Text)
    evidence: so.Mapped[Optional[str]] = so.mapped_column(sa.Text)  # proof of concept or request/response
    false_positive: so.Mapped[bool] = so.mapped_column(sa.Boolean, default=False)

    
    # Relationships
    scan: so.Mapped["Scan"] = so.relationship("Scan", back_populates="vulnerabilities")
    tool_result: so.Mapped[Optional["ToolResult"]] = so.relationship("ToolResult", back_populates="vulnerabilities")
    

    @property
    def severity_score(self) -> int:
        """Convert severity to numeric score for sorting."""
        severity_map = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return severity_map.get(self.severity.lower(), 0)

    @property
    def severity_color(self) -> str:
        """Get Bootstrap color class for severity."""
        color_map = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'secondary',
            'info': 'light'
        }
        return color_map.get(self.severity.lower(), 'secondary')

    def __repr__(self) -> str:
        return f'<Vulnerability {self.title} ({self.severity})>'

class Report(TimestampMixin, db.Model):
    """Reports generated for scans."""
    __tablename__ = 'reports'

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    scan_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('scans.id'), nullable=False, index=True)
    report_type: so.Mapped[str] = so.mapped_column(sa.String(20), nullable=False)  # html, pdf, json
    file_path: so.Mapped[Optional[str]] = so.mapped_column(sa.String(500))
    file_size: so.Mapped[Optional[int]] = so.mapped_column(sa.Integer)  # in bytes
    generated_at: so.Mapped[datetime] = so.mapped_column(
        sa.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    download_count: so.Mapped[int] = so.mapped_column(sa.Integer, default=0)
    is_public: so.Mapped[bool] = so.mapped_column(sa.Boolean, default=False)
    public_token: so.Mapped[Optional[str]] = so.mapped_column(sa.String(255))
    expires_at: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))

    # Relationships
    scan: so.Mapped["Scan"] = so.relationship("Scan", back_populates="reports")

    @property
    def is_expired(self) -> bool:
        """Check if the report has expired."""
        if self.expires_at:
            return datetime.now(timezone.utc) > self.expires_at
        return False

    @property
    def file_size_human(self) -> str:
        """Get human-readable file size."""
        if not self.file_size:
            return "Unknown"
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if self.file_size < 1024.0:
                return f"{self.file_size:.1f} {unit}"
            self.file_size /= 1024.0
        return f"{self.file_size:.1f} TB"

    def __repr__(self) -> str:
        return f'<Report {self.report_type} for Scan {self.scan_id}>'

class ApiKey(TimestampMixin, db.Model):
    """API keys for programmatic access."""
    __tablename__ = 'api_keys'

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('users.id'), nullable=False, index=True)
    key_name: so.Mapped[Optional[str]] = so.mapped_column(sa.String(100))
    api_key: so.Mapped[str] = so.mapped_column(sa.String(255), unique=True, nullable=False, index=True)
    is_active: so.Mapped[bool] = so.mapped_column(sa.Boolean, default=True)
    last_used_at: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))
    expires_at: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))
    rate_limit: so.Mapped[int] = so.mapped_column(sa.Integer, default=100)  # requests per hour

    # Relationships
    user: so.Mapped["User"] = so.relationship("User", back_populates="api_keys")

    @property
    def is_expired(self) -> bool:
        """Check if the API key has expired."""
        if self.expires_at:
            return datetime.now(timezone.utc) > self.expires_at
        return False

    @property
    def is_valid(self) -> bool:
        """Check if the API key is valid (active and not expired)."""
        return self.is_active and not self.is_expired

    @property
    def masked_key(self) -> str:
        """Get masked API key for display (show first 8 and last 4 characters)."""
        if len(self.api_key) < 12:
            return self.api_key
        return f"{self.api_key[:8]}...{self.api_key[-4:]}"

    def __repr__(self) -> str:
        return f'<ApiKey {self.key_name or "Unnamed"} for User {self.user_id}>'

class ConsentLog(db.Model):
    """Consent logs for legal compliance."""
    __tablename__ = 'consent_logs'

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('users.id'), nullable=False, index=True)
    scan_id: so.Mapped[Optional[int]] = so.mapped_column(sa.ForeignKey('scans.id'))
    target_url: so.Mapped[Optional[str]] = so.mapped_column(sa.String(500))
    consent_text: so.Mapped[str] = so.mapped_column(sa.Text, nullable=False)
    ip_address: so.Mapped[Optional[str]] = so.mapped_column(sa.String(45))
    user_agent: so.Mapped[Optional[str]] = so.mapped_column(sa.Text)
    agreed_at: so.Mapped[datetime] = so.mapped_column(
        sa.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    user: so.Mapped["User"] = so.relationship("User", back_populates="consent_logs")
    scan: so.Mapped[Optional["Scan"]] = so.relationship("Scan", back_populates="consent_logs")

    def __repr__(self) -> str:
        return f'<ConsentLog User {self.user_id} at {self.agreed_at}>'

class Subscription(TimestampMixin, db.Model):
    """Subscription tracking for billing integration."""
    __tablename__ = 'subscriptions'

    id: so.Mapped[int] = so.mapped_column(primary_key=True)
    user_id: so.Mapped[int] = so.mapped_column(sa.ForeignKey('users.id'), nullable=False, index=True)
    stripe_subscription_id: so.Mapped[Optional[str]] = so.mapped_column(sa.String(255))
    plan_name: so.Mapped[str] = so.mapped_column(sa.String(50), nullable=False)
    status: so.Mapped[str] = so.mapped_column(sa.String(20), default='active')  # active, cancelled, past_due
    current_period_start: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))
    current_period_end: so.Mapped[Optional[datetime]] = so.mapped_column(sa.DateTime(timezone=True))
    monthly_scan_limit: so.Mapped[int] = so.mapped_column(sa.Integer, default=10)
    scans_used_this_month: so.Mapped[int] = so.mapped_column(sa.Integer, default=0)

    # Relationships
    user: so.Mapped["User"] = so.relationship("User", back_populates="subscriptions")

    @property
    def is_active(self) -> bool:
        """Check if subscription is active."""
        return self.status == 'active'

    @property
    def scans_remaining(self) -> int:
        """Calculate remaining scans for current period."""
        return max(0, self.monthly_scan_limit - self.scans_used_this_month)

    @property
    def usage_percentage(self) -> float:
        """Calculate usage percentage for current period."""
        if self.monthly_scan_limit == 0:
            return 100.0
        return (self.scans_used_this_month / self.monthly_scan_limit) * 100

    def __repr__(self) -> str:
        return f'<Subscription {self.plan_name} for User {self.user_id} ({self.status})>'

    
@login.user_loader
def load_user(user_id: int):
    """Load a user by their ID."""
    return db.session.get(User, int(user_id))
def get_user_by_email(email: str) -> Optional[User]:
    """Get a user by email address."""
    return db.session.scalar(
        sa.select(User).where(User.email == email)
    )


def get_user_by_username(username: str) -> Optional[User]:
    """Get a user by username."""
    return db.session.scalar(
        sa.select(User).where(User.username == username)
    )


def get_user_scans(user_id: int, limit: int = 10) -> List[Scan]:
    """Get recent scans for a user."""
    return list(db.session.scalars(
        sa.select(Scan)
        .where(Scan.user_id == user_id)
        .order_by(Scan.created_at.desc())
        .limit(limit)
    ))


def get_scan_with_vulnerabilities(scan_id: int) -> Optional[Scan]:
    """Get a scan with its vulnerabilities loaded."""
    return db.session.scalar(
        sa.select(Scan)
        .options(so.selectinload(Scan.vulnerabilities))
        .where(Scan.id == scan_id)
    )


def get_active_subscription(user_id: int) -> Optional[Subscription]:
    """Get the active subscription for a user."""
    return db.session.scalar(
        sa.select(Subscription)
        .where(Subscription.user_id == user_id)
        .where(Subscription.status == 'active')
        .order_by(Subscription.created_at.desc())
    )


def can_user_create_scan(user_id: int) -> bool:
    """Check if user can create a new scan based on their subscription."""
    subscription = get_active_subscription(user_id)
    if not subscription:
        return False  # No active subscription
    
    return subscription.scans_remaining > 0