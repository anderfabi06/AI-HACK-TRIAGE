import json
import re
from .generic_parser import clean_ansi

SENSITIVE_KEYWORDS = (
    ".env", ".git", "admin", "backup", "bak", "config", "swagger", 
    "graphql", "phpinfo", "actuator", "console", "api/v", "database",
    "db", "dump", "root", "secret", "private", "id_rsa", "login", "dashboard"
)

def is_sensitive_path(path: str) -> bool:
    """Detecta si la ruta encontrada por ffuf apunta a un activo o endpoint de alto interés."""
    path_lower = path.lower()
    return any(keyword in path_lower for keyword in SENSITIVE_KEYWORDS)

def parse_ffuf_json(content: str) -> str:
    """Parsea la salida JSON oficial de ffuf (-of json -o salida.json)."""
    try:
        data = json.loads(content)
    except Exception:
        return ""

    commandline = data.get("commandline", "")
    results = data.get("results", [])
    if not results and not isinstance(results, list):
        return ""

    status_200 = []
    status_redirect = []
    status_auth = []
    status_errors = []
    status_other = []

    seen = set()

    for item in results:
        url = item.get("url") or ""
        fuzz_input = item.get("input", {})
        fuzz_word = ""
        if isinstance(fuzz_input, dict):
            fuzz_word = list(fuzz_input.values())[0] if fuzz_input else ""
        elif isinstance(fuzz_input, str):
            fuzz_word = fuzz_input

        path_display = fuzz_word or url
        if not path_display:
            continue

        status = item.get("status", 0)
        length = item.get("length", 0)
        redirect = item.get("redirectlocation", "")

        key = (path_display, status, length)
        if key in seen:
            continue
        seen.add(key)

        line_str = f"  - /{path_display.lstrip('/')} (Size: {length})"
        if redirect:
            line_str += f" -> Redirect: {redirect}"

        if is_sensitive_path(path_display):
            line_str += "  [!] RUTA CRÍTICA/SENSIBLE"

        if status == 200:
            status_200.append(line_str)
        elif status in (301, 302, 307, 308):
            status_redirect.append(f"  [Status {status}] /{path_display.lstrip('/')} (Size: {length}) -> {redirect or 'N/A'}")
        elif status in (401, 403):
            status_auth.append(f"  [Status {status}] /{path_display.lstrip('/')} (Size: {length})")
        elif status >= 500:
            status_errors.append(f"  [Status {status}] /{path_display.lstrip('/')} (Size: {length}) [!] Error del Servidor")
        else:
            status_other.append(f"  [Status {status}] /{path_display.lstrip('/')} (Size: {length})")

    output = ["=== FFUF WEB DIRECTORY & PARAMETER FUZZING SUMMARY ==="]
    if commandline:
        # Extraer objetivo del comando
        target_m = re.search(r'-u\s+([^\s]+)', commandline)
        if target_m:
            output.append(f"Target: {target_m.group(1)}")

    if status_200:
        output.append(f"\n[Endpoints y Archivos Accesibles (Status 200 OK) - {len(status_200)} encontrados]")
        output.extend(status_200[:25])
        if len(status_200) > 25:
            output.append(f"  [...] {len(status_200) - 25} rutas adicionales status 200 omitidas para brevedad.")

    if status_redirect:
        output.append(f"\n[Redirecciones y Paneles (Status 301/302) - {len(status_redirect)} encontrados]")
        output.extend(status_redirect[:20])

    if status_auth:
        output.append(f"\n[Rutas Protegidas o Restringidas (Status 401/403) - {len(status_auth)} encontrados]")
        output.extend(status_auth[:20])

    if status_errors:
        output.append(f"\n[Respuestas con Error Interno (Status 500+) - {len(status_errors)} encontrados]")
        output.extend(status_errors[:10])

    return "\n".join(output)

def parse_ffuf_text(content: str) -> str:
    """Parsea la salida de terminal en texto plano estándar de ffuf."""
    clean_text = clean_ansi(content)
    lines = clean_text.splitlines()

    target_url = ""
    status_200 = []
    status_redirect = []
    status_auth = []
    status_errors = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Capturar URL objetivo
        if stripped.startswith(":: URL"):
            url_m = re.search(r':: URL\s*:\s*(.+)', stripped)
            if url_m:
                target_url = url_m.group(1).strip()
            continue

        # Descartar banners de inicio de ffuf y separadores
        if stripped.startswith("::") or stripped.startswith("___") or "Starting ffuf" in stripped:
            continue

        # Formato estándar ffuf en CLI:
        # ruta   [Status: 200, Size: 123, Words: 12, Lines: 3, Duration: 20ms]
        m = re.search(r'^([^\s\[]+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)', stripped)
        if m:
            path = m.group(1)
            status = int(m.group(2))
            size = m.group(3)

            # Descartar 404s
            if status == 404:
                continue

            entry = f"  - /{path.lstrip('/')} (Status: {status}, Size: {size})"
            if is_sensitive_path(path):
                entry += "  [!] RUTA SENSIBLE / IMPACTO POTENCIAL"

            if status == 200:
                status_200.append(entry)
            elif status in (301, 302, 307, 308):
                status_redirect.append(entry)
            elif status in (401, 403):
                status_auth.append(entry)
            elif status >= 500:
                status_errors.append(entry)

    output = ["=== FFUF WEB DIRECTORY & PARAMETER FUZZING SUMMARY ==="]
    if target_url:
        output.append(f"Target: {target_url}")

    if status_200:
        output.append(f"\n[Endpoints Accesibles (Status 200 OK) - {len(status_200)} encontrados]")
        output.extend(status_200[:25])
    if status_redirect:
        output.append(f"\n[Redirecciones (Status 301/302) - {len(status_redirect)} encontrados]")
        output.extend(status_redirect[:15])
    if status_auth:
        output.append(f"\n[Rutas Restringidas (Status 401/403) - {len(status_auth)} encontrados]")
        output.extend(status_auth[:15])
    if status_errors:
        output.append(f"\n[Errores del Servidor (Status 500+) - {len(status_errors)} encontrados]")
        output.extend(status_errors[:10])

    return "\n".join(output) if len(output) > 1 else clean_text

def parse_ffuf(content: str) -> str:
    """Punto de entrada principal para parsear ffuf (tanto en JSON como en texto de consola)."""
    stripped = content.strip()
    if not stripped:
        return ""

    # Caso 1: Archivo JSON de ffuf
    if stripped.startswith("{") and '"results"' in stripped:
        parsed_json = parse_ffuf_json(stripped)
        if parsed_json:
            return parsed_json

    # Caso 2: Texto CLI
    return parse_ffuf_text(content)

