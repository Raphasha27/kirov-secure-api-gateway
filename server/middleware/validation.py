import json
import re
from typing import Any, Callable, Dict, Type

from fastapi import HTTPException, Request, status
from pydantic import BaseModel, ValidationError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

SQL_INJECTION_PATTERN = re.compile(
    r"(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC|EXECUTE|OR\s+1=1)\b)",
    re.IGNORECASE,
)


def has_sql_injection(value: str) -> bool:
    cleaned = re.sub(r"'.*?'", "", value)
    cleaned = re.sub(r'".*?"', "", cleaned)
    return bool(SQL_INJECTION_PATTERN.search(cleaned))


def sanitize_input(value: str) -> str:
    return value.replace("<", "&lt;").replace(">", "&gt;")


class InputSanitizationMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Any:
        for param, values in request.query_params.multi_items():
            if has_sql_injection(param) or has_sql_injection(values):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Suspicious input detected in query parameter: {param}",
                )

        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            body_bytes = await request.body()
            if body_bytes:
                try:
                    body_str = body_bytes.decode("utf-8")
                    body_json = json.loads(body_str)
                    _check_json_for_injection(body_json)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass

        response = await call_next(request)
        return response


def _check_json_for_injection(obj: Any, path: str = "") -> None:
    if isinstance(obj, str):
        if has_sql_injection(obj):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Suspicious input detected in body field: {path}",
            )
    elif isinstance(obj, dict):
        for key, value in obj.items():
            _check_json_for_injection(value, f"{path}.{key}" if path else key)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _check_json_for_injection(item, f"{path}[{i}]")


def validate_schema(model: Type[BaseModel]) -> Callable:
    def validator(payload: Dict[str, Any]) -> BaseModel:
        try:
            return model(**payload)
        except ValidationError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=[{"loc": err["loc"], "msg": err["msg"]} for err in e.errors()],
            )

    return validator
