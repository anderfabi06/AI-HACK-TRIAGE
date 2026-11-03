import re
from .generic_parser import clean_ansi

def parse_nikto(content: str) -> str:
    """
    Parsea y optimiza los resultados de Nikto:
    - Extrae el Host y Puerto objetivo.
    - Captura exposiciones de tecnología (banners, WAFs, proxies, origin servers).
    - Captura vulnerabilidades y malas configuraciones reales (BREACH, cabeceras faltantes de impacto,
      métodos HTTP peligrosos, rutas sensibles expuestas como /admin, .git, etc.).
    - Elimina ruido: enlaces genéricos a documentación de Mozilla/Nikto, advertencias de proxy
      y encabezados aleatorios de depuración (ej. rndr-id).
    """
    clean_text = clean_ansi(content)
    lines = clean_text.splitlines()

    target_host = ""
    target_port = ""
    tech_findings = []
    vuln_findings = []
    exposed_endpoints = []
    
    in_ssl_info = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # 1. Host y Puerto
        host_m = re.search(r'Target Host:\s*([^\s]+)', stripped)
        if host_m:
            target_host = host_m.group(1)
            continue
        port_m = re.search(r'Target Port:\s*(\d+)', stripped)
        if port_m:
            target_port = port_m.group(1)
            continue

        # Descartar versiones de Nikto y enlaces redundantes
        if stripped.startswith("- Nikto") or stripped.startswith("+ End Time:"):
            continue

        # 2. Tecnologías detectadas y WAF/CDN
        if "Cloudflare detected" in stripped or "WAF" in stripped:
            tech_findings.append("  [+] CDN/WAF: Cloudflare detectado (cf-ray header)")
            continue
        
        # Banners de servidor origen o servidor web
        origin_m = re.search(r"'(x-render-origin-server|Server|x-powered-by)' found, with contents:\s*(.+)", stripped, re.IGNORECASE)
        if origin_m:
            header_name = origin_m.group(1)
            header_val = origin_m.group(2).strip().rstrip('.')
            tech_findings.append(f"  [+] Tecnología/Servidor expuesto ({header_name}): {header_val}")
            continue

        # Descartar headers de tracking sin valor de seguridad (rndr-id, x-request-id, etc.)
        if re.search(r"Uncommon header\(s\) '(rndr-id|x-request-id|cf-ray|x-amz-cf-id)'", stripped, re.IGNORECASE):
            continue

        # Descartar avisos sobre incapacidad de Nikto para probar HTTP/3
        if "advertising HTTP/3" in stripped or "Nikto cannot test" in stripped:
            continue

        # 3. Sección SSL resumida
        if stripped.startswith("+ SSL Info:"):
            in_ssl_info = True
            continue
        if in_ssl_info:
            if stripped.startswith("+") and not stripped.startswith("+ SSL Info:"):
                in_ssl_info = False
            else:
                # Ya testssl/sslscan cubren SSL a fondo, así que aquí solo nos fijamos en la suite
                continue

        # 4. Vulnerabilidades y hallazgos reales (BREACH, rutas, inyecciones, métodos)
        # Limpiar enlaces del tipo "See: https://..." al final de la línea
        clean_finding = re.sub(r'See:\s*https?://[^\s]+:?', '', stripped).strip()
        # Quitar la recomendación genérica de usar proxy
        clean_finding = re.sub(r'Recommend proxying via [^.]+\.', '', clean_finding).strip()

        if any(v in clean_finding.lower() for v in ("vulnerable", "breach", "anti-clickjacking", "x-frame-options", "directory indexing", "interesting", "cve-", "method", "put", "delete", "trace")):
            vuln_findings.append(f"  [!] {clean_finding}")
        elif re.search(r'\+ (GET|POST|HEAD) [^:]+:\s*(.+)', clean_finding):
            # Endpoints o respuestas específicas
            exposed_endpoints.append(f"  [*] {clean_finding}")

    # Consolidar salida estructurada
    output = ["=== NIKTO AUDIT SUMMARY ==="]
    if target_host:
        target_str = f"Target: {target_host}"
        if target_port:
            target_str += f":{target_port}"
        output.append(target_str)

    if tech_findings:
        output.append("\n[Tecnologías & Perímetro]")
        output.extend(tech_findings)

    if vuln_findings:
        output.append("\n[Vulnerabilidades & Configuraciones Inseguras]")
        output.extend(vuln_findings)

    if exposed_endpoints:
        output.append("\n[Endpoints y Observaciones Relevantes]")
        output.extend(exposed_endpoints[:10])

    return "\n".join(output) if len(output) > 1 else clean_text
