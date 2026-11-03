import re
import xml.etree.ElementTree as ET
from .generic_parser import clean_ansi

def parse_nmap_xml(xml_content: str) -> str:
    """Extrae hosts, puertos abiertos, servicios y scripts vulnerables desde XML de Nmap."""
    try:
        root = ET.fromstring(xml_content)
        extracted = []

        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            # Obtener direcciones IP/MAC
            addresses = [addr.get("addr") for addr in host.findall("address") if addr.get("addr")]
            addr_str = ", ".join(addresses) if addresses else "Host desconocido"

            # Hostnames
            hostnames_elem = host.find("hostnames")
            hostnames = []
            if hostnames_elem is not None:
                hostnames = [hn.get("name") for hn in hostnames_elem.findall("hostname") if hn.get("name")]
            hn_str = f" ({', '.join(hostnames)})" if hostnames else ""

            host_header = f"=== HOST: {addr_str}{hn_str} ==="
            extracted.append(host_header)

            # OS detection
            os_match = host.find("os/osmatch")
            if os_match is not None:
                extracted.append(f"  OS Estimado: {os_match.get('name')} (Precisión: {os_match.get('accuracy')}%)")

            # Puertos
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port in ports_elem.findall("port"):
                    state_elem = port.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue

                    port_id = port.get("portid")
                    proto = port.get("protocol")
                    service = port.find("service")
                    srv_name = service.get("name", "unknown") if service is not None else "unknown"
                    srv_product = service.get("product", "") if service is not None else ""
                    srv_version = service.get("version", "") if service is not None else ""
                    srv_extra = service.get("extrainfo", "") if service is not None else ""

                    version_full = f"{srv_product} {srv_version} {srv_extra}".strip()
                    extracted.append(f"  [+] Puerto: {port_id}/{proto} | Servicio: {srv_name} | Versión: {version_full or 'N/A'}")

                    # Scripts de vulnerabilidades / banners
                    for script in port.findall("script"):
                        s_id = script.get("id", "")
                        s_out = script.get("output", "").strip()
                        if s_out:
                            # Truncar salidas de scripts excesivamente largas
                            s_out_clean = s_out.replace("\n", " ")
                            if len(s_out_clean) > 250:
                                s_out_clean = s_out_clean[:250] + "..."
                            extracted.append(f"      Script [{s_id}]: {s_out_clean}")

        if extracted:
            return "\n".join(extracted)
    except Exception:
        pass
    return ""

def parse_nmap_text(text_content: str) -> str:
    """Extrae líneas relevantes de un escaneo de texto de Nmap descartando puertos cerrados y ruido."""
    text_content = clean_ansi(text_content)
    lines = text_content.splitlines()
    filtered = []
    
    in_port_section = False
    skip_keywords = (
        "Starting Nmap",
        "Nmap done at",
        "Read data files from",
        "Service detection performed",
        "SYN Stealth Scan Timing",
        "packets received",
        "OS and Service detection performed"
    )

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if any(stripped.startswith(k) for k in skip_keywords):
            continue

        # Detectar cabecera de host
        if "Nmap scan report for" in stripped:
            filtered.append(f"\n{stripped}")
            in_port_section = True
            continue

        # Omitir resumen masivo de puertos cerrados o filtrados
        if re.search(r'Not shown: \d+ (closed|filtered)', stripped):
            filtered.append(f"  [i] {stripped}")
            continue

        # Puertos abiertos o scripts
        if in_port_section:
            # Línea de cabecera de tabla de puertos
            if stripped.startswith("PORT ") or re.match(r'^\d+/(tcp|udp)\s+open', stripped):
                filtered.append(f"  {stripped}")
            elif stripped.startswith("|") or stripped.startswith("|_"):
                filtered.append(f"    {stripped}")
            elif stripped.startswith("Service Info:") or stripped.startswith("OS details:") or stripped.startswith("Running:"):
                filtered.append(f"  {stripped}")

    return "\n".join(filtered) if filtered else text_content

def parse_nmap(content: str) -> str:
    """Punto de entrada para parsear Nmap en XML o texto plano."""
    stripped = content.strip()
    if stripped.startswith("<?xml") or "<nmaprun" in stripped:
        parsed_xml = parse_nmap_xml(stripped)
        if parsed_xml:
            return parsed_xml
    return parse_nmap_text(content)

