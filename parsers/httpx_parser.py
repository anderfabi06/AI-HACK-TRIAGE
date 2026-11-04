import json
import re
from .generic_parser import clean_ansi

def _extract_from_json_dict(entry: dict) -> dict:
    """Extrae campos relevantes de un objeto JSON de httpx."""
    url = entry.get("url") or entry.get("input") or entry.get("host") or ""
    status = entry.get("status_code") or entry.get("status-code") or entry.get("status") or 0
    try:
        status = int(status)
    except (ValueError, TypeError):
        status = 0

    title = entry.get("title") or ""
    webserver = entry.get("webserver") or ""
    location = entry.get("location") or ""
    tech = entry.get("tech") or entry.get("technologies") or []
    if isinstance(tech, list):
        tech_str = ", ".join(str(t) for t in tech if t)
    elif isinstance(tech, str):
        tech_str = tech
    else:
        tech_str = ""

    content_length = entry.get("content_length") or entry.get("content-length") or ""

    return {
        "url": url,
        "status": status,
        "title": title.strip(),
        "webserver": webserver.strip(),
        "location": location.strip(),
        "tech": tech_str.strip(),
        "length": str(content_length).strip()
    }

def _format_httpx_entry(item: dict) -> str:
    """Da formato a una entrada procesada de httpx."""
    parts = [item["url"]]
    details = []
    if item["status"]:
        details.append(f"Status: {item['status']}")
    if item["length"]:
        details.append(f"Size: {item['length']}")
    if item["title"]:
        details.append(f"Title: \"{item['title']}\"")
    if item["webserver"]:
        details.append(f"Server: {item['webserver']}")
    if item["tech"]:
        details.append(f"Tech: [{item['tech']}]")
    if item["location"]:
        details.append(f"Redirect: {item['location']}")

    if details:
        return f"  - {parts[0]} ({', '.join(details)})"
    return f"  - {parts[0]}"

def parse_httpx_json(content: str) -> str:
    """
    Parsea salidas de httpx en JSON: tanto JSONL (un JSON por línea)
    como JSON Array ([ { ... }, { ... } ]).
    """
    entries = []
    stripped = content.strip()

    # Intentar como JSON Array o único JSON
    if (stripped.startswith("[") and stripped.endswith("]")) or (stripped.startswith("{") and stripped.endswith("}")):
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                entries = [data]
        except Exception:
            entries = []

    # Si no cargó como array único, procesar línea a línea (JSONL clásico de httpx -json)
    if not entries:
        for line in stripped.splitlines():
            line_s = line.strip()
            if not line_s or not line_s.startswith("{"):
                continue
            try:
                obj = json.loads(line_s)
                if isinstance(obj, dict):
                    entries.append(obj)
            except Exception:
                continue

    if not entries:
        return ""

    parsed_items = [_extract_from_json_dict(e) for e in entries if isinstance(e, dict)]
    return _summarize_httpx_items(parsed_items)

def parse_httpx_text(content: str) -> str:
    """
    Parsea la salida en texto plano de httpx.
    Soporta formato con corchetes estándar de httpx:
    ej: https://example.com [200, OK] [Apache] [Title]
    o simplemente URLs con códigos.
    """
    cleaned = clean_ansi(content)
    parsed_items = []

    for line in cleaned.splitlines():
        line_s = line.strip()
        if not line_s:
            continue

        # Descartar banners o líneas informativas
        if line_s.startswith("__") or "httpx" in line_s.lower() and "http" not in line_s:
            continue

        # Extraer URL al inicio
        url_match = re.match(r'^(https?://[^\s\[]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\[]*)?)', line_s)
        if not url_match:
            continue

        url = url_match.group(1)
        rest = line_s[len(url):].strip()

        # Extraer bloques entre corchetes [ ... ]
        bracket_blocks = re.findall(r'\[(.*?)\]', rest)

        status = 0
        title = ""
        webserver = ""
        tech = ""
        location = ""

        for block in bracket_blocks:
            block_s = block.strip()
            # Status code (ej: 200, 200, OK, 403, Forbidden, 301)
            status_match = re.search(r'\b([1-5]\d{2})\b', block_s)
            if status_match and status == 0:
                try:
                    status = int(status_match.group(1))
                except ValueError:
                    pass
                # Si el bloque contiene una redirección (ej: 301, https://...)
                if "http" in block_s:
                    redirect_match = re.search(r'(https?://[^\s,]+)', block_s)
                    if redirect_match:
                        location = redirect_match.group(1)
                continue

            # Si es servidor o tech
            if any(s in block_s.lower() for s in ("nginx", "apache", "cloudflare", "microsoft-iis", "caddy", "litespeed")):
                if not webserver:
                    webserver = block_s
                else:
                    tech = f"{tech}, {block_s}" if tech else block_s
            elif not title and len(block_s) > 1:
                title = block_s
            else:
                tech = f"{tech}, {block_s}" if tech else block_s

        parsed_items.append({
            "url": url,
            "status": status,
            "title": title,
            "webserver": webserver,
            "location": location,
            "tech": tech,
            "length": ""
        })

    return _summarize_httpx_items(parsed_items)

def _summarize_httpx_items(items: list) -> str:
    """Clasifica y resume los elementos recolectados de httpx."""
    if not items:
        return ""

    status_200 = []
    status_redirect = []
    status_auth = []
    status_errors = []
    status_other = []

    seen = set()

    for item in items:
        url = item["url"]
        if not url:
            continue
        status = item["status"]

        # Descartar 404 ruidosos para no saturar tokens
        if status == 404:
            continue

        key = (url, status, item.get("title", ""))
        if key in seen:
            continue
        seen.add(key)

        formatted = _format_httpx_entry(item)
        if status == 200:
            status_200.append(formatted)
        elif status in (301, 302, 307, 308):
            status_redirect.append(formatted)
        elif status in (401, 403):
            status_auth.append(formatted)
        elif status >= 500:
            status_errors.append(formatted)
        else:
            status_other.append(formatted)

    output = ["=== HTTPX PROBE & ASSET RESOLUTION SUMMARY ==="]

    if status_200:
        output.append(f"\n[Endpoints y Servicios Web Activos (Status 200 OK) - {len(status_200)} encontrados]")
        output.extend(status_200[:30])
        if len(status_200) > 30:
            output.append(f"  [...] {len(status_200) - 30} endpoints adicionales status 200 omitidos para brevedad.")

    if status_redirect:
        output.append(f"\n[Redirecciones Detectadas (Status 301/302) - {len(status_redirect)} encontrados]")
        output.extend(status_redirect[:20])

    if status_auth:
        output.append(f"\n[Endpoints con Acceso Restringido (Status 401/403) - {len(status_auth)} encontrados]")
        output.extend(status_auth[:20])

    if status_errors:
        output.append(f"\n[Errores del Servidor (Status 500+) - {len(status_errors)} encontrados]")
        output.extend(status_errors[:15])

    if status_other:
        output.append(f"\n[Otros Endpoints / Respuestas Inusuales - {len(status_other)} encontrados]")
        output.extend(status_other[:15])

    return "\n".join(output)

def parse_httpx(content: str) -> str:
    """
    Punto de entrada principal para httpx.
    Detecta automáticamente si el contenido es JSON (Array o JSONL) o Texto Plano.
    """
    stripped = clean_ansi(content).strip()
    if not stripped:
        return ""

    # Detección de JSON / JSONL
    if stripped.startswith("{") or stripped.startswith("["):
        parsed = parse_httpx_json(stripped)
        if parsed:
            return parsed

    # Si tiene líneas JSON intermedias
    first_line = stripped.split("\n", 1)[0].strip()
    if first_line.startswith("{") and first_line.endswith("}"):
        parsed = parse_httpx_json(stripped)
        if parsed:
            return parsed

    # Fallback a texto plano estructurado
    parsed_txt = parse_httpx_text(content)
    if parsed_txt:
        return parsed_txt

    return clean_ansi(content)[:2000]
