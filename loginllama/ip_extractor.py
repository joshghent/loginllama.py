import re
from typing import Optional, Any

PRIVATE_IP_RANGES = [
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^127\."),
    re.compile(r"^::1$"),
    re.compile(r"^fc00:"),
    re.compile(r"^fe80:"),
]


class IPExtractor:
    """
    Extracts IP address from request with multi-source priority fallback
    and private IP filtering for proxy/CDN scenarios.
    """

    @staticmethod
    def extract(request: Any) -> Optional[str]:
        """
        Extract IP address from request with priority fallback

        Priority order:
        1. X-Forwarded-For (first non-private IP)
        2. CF-Connecting-IP (Cloudflare)
        3. X-Real-IP (nginx)
        4. True-Client-IP (Akamai/Cloudflare)
        5. Direct connection IP

        Args:
            request: Django/Flask/FastAPI request object

        Returns:
            IP address or None
        """
        if not request:
            return None

        # Priority 1: X-Forwarded-For
        x_forwarded_for = IPExtractor._get_header(request, "X-Forwarded-For")
        if x_forwarded_for:
            ip = IPExtractor._parse_forwarded_for(x_forwarded_for)
            if ip:
                return ip

        # Priority 2: CF-Connecting-IP
        cf_ip = IPExtractor._get_header(request, "CF-Connecting-IP")
        if cf_ip and IPExtractor._is_valid_public_ip(cf_ip):
            return cf_ip

        # Priority 3: X-Real-IP
        real_ip = IPExtractor._get_header(request, "X-Real-IP")
        if real_ip and IPExtractor._is_valid_public_ip(real_ip):
            return real_ip

        # Priority 4: True-Client-IP
        true_client_ip = IPExtractor._get_header(request, "True-Client-IP")
        if true_client_ip and IPExtractor._is_valid_public_ip(true_client_ip):
            return true_client_ip

        # Priority 5: Direct connection
        return IPExtractor._get_direct_ip(request)

    @staticmethod
    def _parse_forwarded_for(header: str) -> Optional[str]:
        """
        Parse X-Forwarded-For header and return first public IP
        Format: "client, proxy1, proxy2"
        """
        ips = [ip.strip() for ip in header.split(",")]
        # Return first public IP in the chain
        for ip in ips:
            if IPExtractor._is_valid_public_ip(ip):
                return ip
        return None

    @staticmethod
    def _is_valid_public_ip(ip: str) -> bool:
        """Check if IP is valid and public (not private/local)"""
        if not IPExtractor._is_valid_ip(ip):
            return False

        for pattern in PRIVATE_IP_RANGES:
            if pattern.match(ip):
                return False

        return True

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IPv4 or IPv6 address format"""
        # IPv4 validation
        ipv4_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
        if ipv4_pattern.match(ip):
            parts = ip.split(".")
            return all(0 <= int(part) <= 255 for part in parts)

        # IPv6 validation (simplified)
        ipv6_pattern = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
        return bool(ipv6_pattern.match(ip))

    @staticmethod
    def _get_header(request: Any, name: str) -> Optional[str]:
        """Get header from request (framework-agnostic)"""
        # Django: META dict with HTTP_ prefix
        if hasattr(request, "META"):
            http_name = f"HTTP_{name.upper().replace('-', '_')}"
            return request.META.get(http_name)

        # Flask/FastAPI: headers dict
        if hasattr(request, "headers"):
            return request.headers.get(name)

        return None

    @staticmethod
    def _get_direct_ip(request: Any) -> Optional[str]:
        """Get direct connection IP"""
        # Django: META['REMOTE_ADDR']
        if hasattr(request, "META"):
            return request.META.get("REMOTE_ADDR")

        # Flask: environ['REMOTE_ADDR']
        if hasattr(request, "environ"):
            return request.environ.get("REMOTE_ADDR")

        # FastAPI: client.host
        if hasattr(request, "client") and request.client:
            return request.client.host

        # Generic: remote_addr attribute
        if hasattr(request, "remote_addr"):
            return request.remote_addr

        return None
