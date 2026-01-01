from contextvars import ContextVar
from typing import Optional, Any, Literal
from .ip_extractor import IPExtractor

# Thread-safe context storage
_request_context: ContextVar[Optional["RequestContext"]] = ContextVar(
    "loginllama_request_context", default=None
)

FrameworkType = Literal["django", "flask", "fastapi", "unknown"]


class RequestContext:
    """Stores extracted request information"""

    def __init__(
        self,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        framework: FrameworkType = "unknown",
        raw_request: Any = None,
    ):
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.framework = framework
        self.raw_request = raw_request


class ContextDetector:
    """
    Context detector for automatically capturing request information
    using contextvars for async-safe context propagation.
    """

    @staticmethod
    def set_context(request: Any) -> None:
        """
        Store request context for this async/thread scope

        Args:
            request: Django/Flask/FastAPI request object
        """
        context = RequestContext(
            ip_address=IPExtractor.extract(request),
            user_agent=ContextDetector._extract_user_agent(request),
            framework=ContextDetector._detect_framework(request),
            raw_request=request,
        )
        _request_context.set(context)

    @staticmethod
    def get_context() -> Optional[RequestContext]:
        """
        Retrieve current request context

        Returns:
            Request context or None if not set
        """
        return _request_context.get()

    @staticmethod
    def clear_context() -> None:
        """Clear the current context"""
        _request_context.set(None)

    @staticmethod
    def _detect_framework(request: Any) -> FrameworkType:
        """Detect which framework the request is from"""
        if not request:
            return "unknown"

        # Django: has META dict and method
        if hasattr(request, "META") and hasattr(request, "method"):
            return "django"

        # Flask: has environ and view_args
        if hasattr(request, "environ") and hasattr(request, "view_args"):
            return "flask"

        # FastAPI: has url and client
        if hasattr(request, "url") and hasattr(request, "client"):
            return "fastapi"

        return "unknown"

    @staticmethod
    def _extract_user_agent(request: Any) -> Optional[str]:
        """Extract User-Agent from request"""
        if not request:
            return None

        # Django
        if hasattr(request, "META"):
            return request.META.get("HTTP_USER_AGENT")

        # Flask
        if hasattr(request, "headers"):
            return request.headers.get("User-Agent")

        # FastAPI
        if hasattr(request, "headers"):
            return request.headers.get("user-agent")

        return None
