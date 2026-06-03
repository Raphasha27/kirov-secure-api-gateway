import json
import logging
import re
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from server.config import settings
from server.models import AuditLog

logger = logging.getLogger("kirov.audit")

SENSITIVE_PATTERNS = re.compile(
    r'"(password|secret|token|api_key|apiKey|authorization|refreshToken)"\s*:\s*"[^"]*"',
    re.IGNORECASE,
)


def sanitize_body(body: str) -> str:
    return SENSITIVE_PATTERNS.sub(r'"\1":"***"', body)


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        body_bytes = await request.body()
        raw_body = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""

        response = await call_next(request)

        sanitized = sanitize_body(raw_body)

        try:
            log_entry = AuditLog(
                user_id=request.headers.get("X-User-ID", ""),
                action=request.method,
                resource=request.url.path,
                resource_id=request.path_params.get("id", None),
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent", "")[:512],
                request_body=sanitized[:4096] if sanitized else None,
                response_status=response.status_code,
            )
            if hasattr(request.state, "db"):
                db = request.state.db
                db.add(log_entry)
                db.commit()
        except Exception as exc:
            logger.warning("Failed to write audit log: %s", exc)

        return response
