import json
import re
from .generic_parser import clean_ansi

SEVERITY_ORDER = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
    "info": 5,
    "unknown": 6
}

def parse_nuclei_json_entries(entries: list) -> str:
    """Procesa una lista de entradas JSON de Nuclei, deduplica y prioriza por severidad."""
    parsed_findings = []
    seen = set()

    for item in entries:
        if not isinstance(item, dict):
            continue

        template_id = item.get("template-id") or item.get("templateID", "unknown-template")
        info = item.get("info", {})
        name = info.get("name", template_id)
        severity = (info.get("severity") or item.get("severity", "info")).lower()
        matched = item.get("matched-at") or item.get("host") or item.get("url", "unknown-target")
        extracted_results = item.get("extracted-results", [])
        
        # Deduplicación por (template, matched)
        key = (template_id, matched)
        if key in seen:
            continue
        seen.add(key)

        finding = {
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "target": matched,
            "extracted": extracted_results,
            "rank": SEVERITY_ORDER.get(severity, 6)
        }
        parsed_findings.append(finding)

    # Ordenar por severidad más crítica primero
    parsed_findings.sort(key=lambda x: x["rank"])

    # Generar salida estructurada compacta
    output_lines = [f"=== NUCLEI DETECTIONS ({len(parsed_findings)} hallazgos únicos) ==="]
    
    info_count = 0
    for f in parsed_findings:
        # Limitar la avalancha de templates 'info' triviales
        if f["severity"] == "info":
            info_count += 1
            if info_count > 15:
                continue

        line = f"[{f['severity'].upper()}] {f['name']} ({f['template_id']}) -> {f['target']}"
        if f["extracted"]:
            line += f" | Extracted: {f['extracted'][:3]}"
        output_lines.append(line)

    if info_count > 15:
        output_lines.append(f"[...] Omitidos {info_count - 15} hallazgos informativos adicionales para optimizar contexto.")

    return "\n".join(output_lines)

def parse_nuclei(content: str) -> str:
    """Punto de entrada para parsear salidas de Nuclei (JSON, JSONL o texto plano)."""
    content = clean_ansi(content).strip()
    if not content:
        return ""

    entries = []

    # Intento 1: Es un array JSON
    if content.startswith("[") and content.endswith("]"):
        try:
            entries = json.loads(content)
            if isinstance(entries, list):
                return parse_nuclei_json_entries(entries)
        except Exception:
            pass

    # Intento 2: JSONL (un JSON por línea)
    jsonl_entries = []
    is_jsonl = False
    for line in content.splitlines():
        line_s = line.strip()
        if line_s.startswith("{") and line_s.endswith("}"):
            try:
                item = json.loads(line_s)
                jsonl_entries.append(item)
                is_jsonl = True
            except Exception:
                pass

    if is_jsonl and jsonl_entries:
        return parse_nuclei_json_entries(jsonl_entries)

    # Intento 3: Formato CLI estándar de Nuclei: [template-id] [protocol] [severity] url
    lines = content.splitlines()
    cli_findings = []
    for line in lines:
        line_s = line.strip()
        if not line_s:
            continue
        # Extraer líneas de alerta
        if re.search(r'\[(critical|high|medium|low|info)\]', line_s, re.IGNORECASE):
            cli_findings.append(line_s)

    if cli_findings:
        return "=== NUCLEI CLI DETECTIONS ===\n" + "\n".join(cli_findings)

    return content

