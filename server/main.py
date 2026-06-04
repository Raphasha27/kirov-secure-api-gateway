import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from server.config import settings
from server.models import Base
from server.middleware.audit import AuditMiddleware
from server.middleware.rate_limit import RateLimitMiddleware
from server.middleware.security_headers import SecurityHeadersMiddleware
from server.middleware.validation import InputSanitizationMiddleware
from server.ai.anomaly_detector import analyze_request

logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("kirov")

engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(InputSanitizationMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuditMiddleware)


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created")


@app.middleware("http")
async def db_session_middleware(request: Request, call_next):
    db = SessionLocal()
    request.state.db = db
    try:
        response = await call_next(request)
        return response
    finally:
        db.close()


@app.middleware("http")
async def anomaly_detection_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    result = analyze_request(
        ip=client_ip,
        endpoint=request.url.path,
        method=request.method,
        user_agent=request.headers.get("user-agent", ""),
    )
    if result.get("is_anomalous"):
        logger.warning(
            "Anomaly detected [%s] %s -> score=%s reason=%s",
            request.method,
            request.url.path,
            result["risk_score"],
            result["reason"],
        )
    response = await call_next(request)
    return response


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
    }


@app.get("/api/v1/status")
def status(request: Request):
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "client_ip": request.client.host if request.client else "unknown",
    }
