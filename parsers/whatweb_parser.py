import json
import re
from .generic_parser import clean_ansi

INTERESTING_PLUGINS = {
    # Servidores y OS
    "httpserver", "apache", "nginx", "iis", "litespeed", "caddy", "openresty",
    # Lenguajes y Runtimes
    "php", "python", "ruby", "perl", "java", "asp_net", "node_js", "x-powered-by",
    # Frameworks y CMS
    "wordpress", "drupal", "joomla", "laravel", "django", "rails", "spring",
    "react", "vue_js", "angular", "bootstrap", "jquery", "express",
    # WAF y CDN
    "cloudflare", "cloudfront", "akamai", "fastly", "imperva", "sucuri",
    # Filtraciones
    "email", "ip", "title", "cookies", "passwordfield"
}

def parse_whatweb_json(content: str) -> str:
    """Parsea el log JSON generado por WhatWeb (--log-json=salida.json)."""
    try:
        data = json.loads(content)
    except Exception:
        return ""

    if not isinstance(data, list):
        if isinstance(data, dict):
            data = [data]
        else:
            return ""

    output = ["=== WHATWEB TECHNOLOGY FINGERPRINTING SUMMARY ==="]

    for entry in data:
        target = entry.get("target", "Target desconocido")
        status = entry.get("http_status", 0)
        plugins = entry.get("plugins", {})

        output.append(f"\n[+] Activo: {target} (Status: {status})")

        servers_os = []
        languages_frameworks = []
        waf_cdn = []
        disclosures = []
        other_tech = []

        for plug_name, plug_info in plugins.items():
            name_lower = plug_name.lower()
            details = []

            # Extraer versiones, cadenas de texto o SO
            if isinstance(plug_info, dict):
                versions = plug_info.get("version", [])
                strings = plug_info.get("string", [])
                os_info = plug_info.get("os", [])
                modules = plug_info.get("module", [])

                if versions:
                    details.append(f"v{', '.join(str(v) for v in versions)}")
                if os_info:
                    details.append(f"OS: {', '.join(str(o) for o in os_info)}")
                if strings:
                    # Limitar cadenas largas
                    s_clean = ", ".join(str(s) for s in strings[:3])
                    if len(s_clean) > 80:
                        s_clean = s_clean[:80] + "..."
                    details.append(s_clean)
                if modules:
                    details.append(f"Módulos: {', '.join(str(m) for m in modules)}")

            detail_str = f" ({' | '.join(details)})" if details else ""
            item_display = f"{plug_name}{detail_str}"

            # Categorizar
            if any(s in name_lower for s in ("server", "apache", "nginx", "iis", "os", "linux", "windows", "ubuntu", "debian")):
                servers_os.append(item_display)
            elif any(w in name_lower for w in ("cloudflare", "cloudfront", "waf", "akamai", "fastly")):
                waf_cdn.append(item_display)
            elif any(l in name_lower for l in ("php", "python", "ruby", "django", "laravel", "express", "asp", "powered", "react", "vue", "angular", "wordpress")):
                languages_frameworks.append(item_display)
            elif any(d in name_lower for d in ("email", "ip", "title", "password")):
                disclosures.append(item_display)
            else:
                if len(other_tech) < 10:
                    other_tech.append(plug_name)

        if servers_os:
            output.append(f"  - Servidor Web & OS: {', '.join(servers_os)}")
        if languages_frameworks:
            output.append(f"  - Lenguajes & Frameworks: {', '.join(languages_frameworks)}")
        if waf_cdn:
            output.append(f"  - Perímetro / WAF: {', '.join(waf_cdn)}")
        if disclosures:
            output.append(f"  - Divulgaciones & Título: {', '.join(disclosures)}")
        if other_tech:
            output.append(f"  - Tecnologías Adicionales: {', '.join(other_tech)}")

    return "\n".join(output) if len(output) > 1 else ""

def parse_whatweb_text(content: str) -> str:
    """Parsea la salida estándar en texto plano / CLI de WhatWeb."""
    clean_text = clean_ansi(content)
    lines = clean_text.splitlines()

    output = ["=== WHATWEB TECHNOLOGY FINGERPRINTING SUMMARY ==="]

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # Formato CLI: http://url [200 OK] Plugin1[val], Plugin2[val] ...
        m = re.match(r'^(https?://[^\s\[]+)\s+\[(\d+[^\]]*)\]\s+(.*)', stripped)
        if m:
            target = m.group(1)
            status = m.group(2)
            tech_raw = m.group(3)

            # Filtrar y limpiar plugins irrelevantes (HTML5, Script, etc.)
            plugins = re.findall(r'([A-Za-z0-9_-]+(?:\[[^\]]*\])*)', tech_raw)
            relevant_plugins = []
            for p in plugins:
                p_name = p.split("[")[0].lower()
                # Omitir cosas obvias que solo ocupan espacio
                if p_name in ("html5", "script", "cookies", "country", "uncommonheaders"):
                    continue
                relevant_plugins.append(p)

            output.append(f"\n[+] Activo: {target} [{status}]")
            output.append(f"  - Tecnologías detectadas: {', '.join(relevant_plugins[:18])}")
        else:
            if not stripped.startswith("WhatWeb report"):
                output.append(f"  {stripped}")

    return "\n".join(output) if len(output) > 1 else clean_text

def parse_whatweb(content: str) -> str:
    """Punto de entrada principal para parsear WhatWeb (JSON y TXT)."""
    stripped = clean_ansi(content).strip()
    if not stripped:
        return ""

    # Caso 1: JSON
    if stripped.startswith("[") or (stripped.startswith("{") and '"plugins"' in stripped):
        start_idx = stripped.find("[")
        if start_idx == -1:
            start_idx = stripped.find("{")
        end_idx = max(stripped.rfind("]"), stripped.rfind("}"))
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            parsed_json = parse_whatweb_json(stripped[start_idx:end_idx+1])
            if parsed_json:
                return parsed_json

    # Caso 2: Texto CLI
    return parse_whatweb_text(content)

