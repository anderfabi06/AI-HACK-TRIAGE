import json
import re
from urllib.parse import urlparse

STATIC_EXTENSIONS = (
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".avi",
    ".mp3", ".wav", ".map"
)

CRITICAL_PATHS = (
    "admin", "login", "auth", "api", "dashboard", "graphql", "swagger",
    "upload", "config", "debug", "console", "actuator", "portal", "user"
)

def is_static_asset(url: str) -> bool:
    """Detecta y descarta imágenes, hojas de estilo y fuentes estáticas irrelevantes."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)

def parse_katana_jsonl(content: str) -> str:
    """Parsea el output JSONL generado por Katana (-j o -json)."""
    endpoints_with_params = []
    api_endpoints = []
    admin_auth_endpoints = []
    other_endpoints = []

    seen = set()
    total_count = 0

    for line in content.splitlines():
        line_s = line.strip()
        if not line_s or not (line_s.startswith("{") and line_s.endswith("}")):
            continue

        try:
            item = json.loads(line_s)
            req = item.get("request", {})
            endpoint = req.get("endpoint") or req.get("url") or item.get("endpoint", "")
            method = req.get("method", "GET")
            status = item.get("response", {}).get("status_code", "")
        except Exception:
            continue

        if not endpoint or is_static_asset(endpoint):
            continue

        total_count += 1
        if endpoint in seen:
            continue
        seen.add(endpoint)

        status_str = f" [{status}]" if status else ""
        item_line = f"  - [{method}] {endpoint}{status_str}"

        parsed_url = urlparse(endpoint)
        query = parsed_url.query
        path_lower = parsed_url.path.lower()

        if query:
            endpoints_with_params.append(item_line + f" (Params: {query[:60]})")
        elif any(api in path_lower for api in ("/api/", "/v1/", "/v2/", "/graphql", "/rest", "/swagger")):
            api_endpoints.append(item_line)
        elif any(crit in path_lower for crit in CRITICAL_PATHS):
            admin_auth_endpoints.append(item_line)
        else:
            other_endpoints.append(item_line)

    return _format_katana_output(total_count, seen, endpoints_with_params, api_endpoints, admin_auth_endpoints, other_endpoints)

def parse_katana_text(content: str) -> str:
    """Parsea una lista de URLs en texto plano generada por Katana (un URL por línea)."""
    endpoints_with_params = []
    api_endpoints = []
    admin_auth_endpoints = []
    other_endpoints = []

    seen = set()
    total_count = 0

    for line in content.splitlines():
        url = line.strip()
        if not url or url.startswith("#") or not url.startswith("http"):
            continue

        if is_static_asset(url):
            continue

        total_count += 1
        if url in seen:
            continue
        seen.add(url)

        item_line = f"  - {url}"
        parsed_url = urlparse(url)
        query = parsed_url.query
        path_lower = parsed_url.path.lower()

        if query:
            endpoints_with_params.append(item_line + f" (Params: {query[:60]})")
        elif any(api in path_lower for api in ("/api/", "/v1/", "/v2/", "/graphql", "/rest", "/swagger")):
            api_endpoints.append(item_line)
        elif any(crit in path_lower for crit in CRITICAL_PATHS):
            admin_auth_endpoints.append(item_line)
        else:
            other_endpoints.append(item_line)

    return _format_katana_output(total_count, seen, endpoints_with_params, api_endpoints, admin_auth_endpoints, other_endpoints)

def _format_katana_output(total_count, seen, with_params, apis, admin_auth, others) -> str:
    if not seen:
        return ""

    output = [
        f"=== KATANA WEB CRAWLER & ENDPOINT DISCOVERY SUMMARY ===",
        f"Total URLs rastreadas: {total_count} | Endpoints únicos relevantes: {len(seen)}"
    ]

    if with_params:
        output.append(f"\n[Endpoints con Parámetros / Vectores de Inyección - {len(with_params)}]")
        output.extend(with_params[:25])
        if len(with_params) > 25:
            output.append(f"  [...] {len(with_params) - 25} endpoints adicionales con parámetros.")

    if apis:
        output.append(f"\n[Endpoints de APIs y Servicios REST/GraphQL - {len(apis)}]")
        output.extend(apis[:20])

    if admin_auth:
        output.append(f"\n[Paneles de Administración, Login y Autenticación - {len(admin_auth)}]")
        output.extend(admin_auth[:15])

    if others and len(with_params) + len(apis) + len(admin_auth) < 10:
        output.append(f"\n[Otras Rutas de Aplicación]")
        output.extend(others[:15])

    return "\n".join(output)

def parse_katana(content: str) -> str:
    """Punto de entrada principal para parsear Katana (JSONL o lista TXT de URLs)."""
    stripped = content.strip()
    if not stripped:
        return ""

    # Caso 1: JSONL
    first_line = stripped.splitlines()[0].strip()
    if first_line.startswith("{") and ("endpoint" in first_line or "request" in first_line):
        parsed = parse_katana_jsonl(stripped)
        if parsed:
            return parsed

    # Caso 2: Texto (URLs línea por línea)
    return parse_katana_text(stripped)

