import json
import logging
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Tuple

from server.config import settings

logger = logging.getLogger("kirov.anomaly")

try:
    import openai

    OPENAI_AVAILABLE = bool(settings.openai_api_key)
except ImportError:
    OPENAI_AVAILABLE = False


class RequestTracker:
    def __init__(self, window_seconds: int = 60, max_entries: int = 1000) -> None:
        self._ip_requests: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=max_entries)
        )
        self._ip_endpoints: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._window = window_seconds

    def record(self, ip: str, endpoint: str, user_agent: str) -> None:
        now = time.monotonic()
        self._ip_requests[ip].append(now)
        self._ip_endpoints[endpoint][ip] += 1

    def _count_in_window(self, ip: str) -> int:
        cutoff = time.monotonic() - self._window
        dq = self._ip_requests.get(ip, deque())
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def check_brute_force(self, ip: str, threshold: int = 30) -> Tuple[bool, int]:
        count = self._count_in_window(ip)
        return count > threshold, count

    def check_data_scraping(
        self, ip: str, endpoint_threshold: int = 15
    ) -> Tuple[bool, List[str]]:
        suspicious: List[str] = []
        for endpoint, ips in self._ip_endpoints.items():
            if ips.get(ip, 0) > endpoint_threshold:
                suspicious.append(endpoint)
        return len(suspicious) > 0, suspicious


tracker = RequestTracker()


def analyze_with_ai(
    ip: str,
    endpoint: str,
    method: str,
    user_agent: str,
    request_count: int,
    brute_force: bool,
    scraping: bool,
) -> Dict[str, Any]:
    if not OPENAI_AVAILABLE:
        return _rule_based_score(ip, endpoint, method, user_agent, request_count, brute_force, scraping)

    try:
        openai.api_key = settings.openai_api_key
        prompt = (
            f"Analyze this API request for anomalies:\n"
            f"- IP: {ip}\n"
            f"- Endpoint: {method} {endpoint}\n"
            f"- User-Agent: {user_agent}\n"
            f"- Requests in last 60s: {request_count}\n"
            f"- Brute force pattern: {brute_force}\n"
            f"- Data scraping pattern: {scraping}\n\n"
            f"Return JSON with fields: risk_score (0-100), is_anomalous (bool), reason (string)"
        )

        resp = openai.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=150,
        )
        content = resp.choices[0].message.content.strip()
        return json.loads(content)
    except Exception as exc:
        logger.warning("OpenAI analysis failed, falling back to rules: %s", exc)
        return _rule_based_score(ip, endpoint, method, user_agent, request_count, brute_force, scraping)


def _rule_based_score(
    ip: str,
    endpoint: str,
    method: str,
    user_agent: str,
    request_count: int,
    brute_force: bool,
    scraping: bool,
) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []

    if brute_force:
        score += 40
        reasons.append(f"Brute force pattern detected ({request_count} requests/min)")

    if scraping:
        score += 30
        reasons.append("Data scraping pattern detected across multiple endpoints")

    if not user_agent or len(user_agent) < 10:
        score += 15
        reasons.append("Missing or suspicious User-Agent")

    if request_count > 50:
        score += 15
        reasons.append("Abnormally high request volume")

    is_anomalous = score >= 50

    return {
        "risk_score": min(score, 100),
        "is_anomalous": is_anomalous,
        "reason": "; ".join(reasons) if reasons else "Normal request pattern",
    }


def analyze_request(
    ip: str,
    endpoint: str,
    method: str,
    user_agent: str = "",
) -> Dict[str, Any]:
    tracker.record(ip, endpoint, user_agent)
    req_count = tracker._count_in_window(ip)
    bf, _ = tracker.check_brute_force(ip)
    sc, _ = tracker.check_data_scraping(ip)

    return analyze_with_ai(ip, endpoint, method, user_agent, req_count, bf, sc)
