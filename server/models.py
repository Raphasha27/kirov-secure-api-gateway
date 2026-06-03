import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON, BigInteger
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    key_hash = Column(String(128), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    user_id = Column(String(255), nullable=False, index=True)
    permissions = Column(JSON, default=list)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(BigInteger, primary_key=True, index=True)
    user_id = Column(String(255), nullable=True, index=True)
    action = Column(String(64), nullable=False)
    resource = Column(String(128), nullable=False)
    resource_id = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
    request_body = Column(Text, nullable=True)
    response_status = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)


class RateLimit(Base):
    __tablename__ = "rate_limits"

    id = Column(BigInteger, primary_key=True, index=True)
    key = Column(String(255), nullable=False, index=True)
    window_start = Column(BigInteger, nullable=False)
    count = Column(Integer, default=0)
