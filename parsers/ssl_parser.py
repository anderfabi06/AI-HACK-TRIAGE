import re
from .generic_parser import clean_ansi

def parse_testssl(content: str) -> str:
    """
    Filtra la salida masiva de testssl.sh (que suele superar los 30.000 caracteres)
    extrayendo únicamente:
    1. Protocolos inseguros/obsoletos habilitados (SSLv2, SSLv3, TLS 1.0, TLS 1.1).
    2. Vulnerabilidades confirmadas o potenciales (VULNERABLE / NOT ok).
    3. Cifrados débiles ofrecidos (CBC, RC4, 3DES, NULL).
    4. Estado del certificado y advertencias de caducidad.
    
    Descarta: pruebas negativas (OK / not vulnerable), simulaciones de clientes
    y listas interminables de ciphers seguros.
    """
    clean_text = clean_ansi(content)
    lines = clean_text.splitlines()
    
    findings = []
    protocols_offered = []
    cert_info = []
    vulnerabilities = []
    cipher_warnings = []
    
    in_cert_section = False
    in_client_simulation = False

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Detectar inicio de simulaciones de clientes (Android, IE, etc.) y omitirlas
        if "Testing client simulations" in stripped or "Client simulations" in stripped:
            in_client_simulation = True
            continue
        if in_client_simulation:
            if "Testing " in stripped or "Done " in stripped:
                in_client_simulation = False
            else:
                continue

        # 1. Protocolos
        proto_match = re.match(r'^(SSLv2|SSLv3|TLS\s*1(\.[0-3])?)\s+(offered|not offered)', stripped, re.IGNORECASE)
        if proto_match:
            proto_name = proto_match.group(1).strip()
            status = proto_match.group(3).lower()
            if "offered" in status and "not offered" not in status:
                if any(bad in proto_name.lower() for bad in ("ssl", "tls 1", "tls 1.0", "tls 1.1")) and "tls 1.2" not in proto_name and "tls 1.3" not in proto_name:
                    protocols_offered.append(f"  [!] PROTOCOLO OBSOLETO HABILITADO: {stripped}")
                else:
                    protocols_offered.append(f"  [+] Protocolo seguro: {stripped}")
            continue

        # 2. Vulnerabilidades conocidas (Heartbleed, POODLE, SWEET32, DROWN, ROBOT, etc.)
        # Solo nos interesan las que NO están OK
        if any(vuln_tag in stripped for vuln_tag in ("(NOT ok)", "VULNERABLE", "potentially NOT ok", "NOT ok")):
            vulnerabilities.append(f"  [!] VULNERABILIDAD TLS: {stripped}")
            continue

        # 3. Categorías de cifrados inseguros
        if any(weak in stripped.lower() for weak in ("null ciphers", "export ciphers", "low: 64 bit", "triple des", "rc4", "cbc ciphers")):
            if "offered" in stripped.lower() and "not offered" not in stripped.lower():
                cipher_warnings.append(f"  [!] CIFRADO DÉBIL ACTIVO: {stripped}")
            continue

        # 4. Sección de Certificado
        if "Testing server defaults (Server Hello)" in stripped or "Server Certificate" in stripped:
            in_cert_section = True
            continue
        if in_cert_section:
            if stripped.startswith("Testing "):
                in_cert_section = False
            elif any(k in stripped.lower() for k in ("issuer", "subject", "signature algorithm", "key size", "expires", "validity", "expired", "self-signed", "trust")):
                cert_info.append(f"  {stripped}")

    # Consolidar salida estructurada ultra-compacta
    output = ["=== TESTSSL AUDIT SUMMARY (Filtrado de Ruido y Hallazgos Relevantes) ==="]
    
    if protocols_offered:
        output.append("\n[Protocolos Soportados]")
        output.extend(protocols_offered)
        
    if vulnerabilities:
        output.append("\n[Vulnerabilidades Criptográficas Detectadas]")
        output.extend(vulnerabilities)
    else:
        output.append("\n[Vulnerabilidades Criptográficas]")
        output.append("  [+] No se detectaron vulnerabilidades críticas comunes (Heartbleed, POODLE, ROBOT, etc. OK).")

    if cipher_warnings:
        output.append("\n[Cifrados y Suites Débiles]")
        output.extend(cipher_warnings)

    if cert_info:
        output.append("\n[Información de Certificado SSL/TLS]")
        output.extend(cert_info[:8])

    return "\n".join(output)

def parse_sslscan(content: str) -> str:
    """
    Filtra la salida de sslscan extrayendo protocolos obsoletos, ciphers inseguros
    y estado del certificado, descartando la lista de ciphers aceptados estándar.
    """
    clean_text = clean_ansi(content)
    lines = clean_text.splitlines()
    
    protocols = []
    weak_ciphers = []
    cert_details = []
    vulns = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Protocolos habilitados
        if re.search(r'^(SSLv[23]|TLSv1\.[0-3])\s+(enabled|disabled)', stripped, re.IGNORECASE):
            if "enabled" in stripped.lower():
                if any(bad in stripped.lower() for bad in ("sslv2", "sslv3", "tlsv1.0", "tlsv1.1")):
                    protocols.append(f"  [!] PROTOCOLO OBSOLETO: {stripped}")
                else:
                    protocols.append(f"  [+] Protocolo moderno: {stripped}")
            continue

        # Cifrados débiles (RC4, 3DES, DES, NULL, export, o marcados como WEAK)
        if any(w in stripped.upper() for w in ("WEAK", "INSECURE", "RC4", "3DES", "DES", "NULL", "EXP")):
            if "accepted" in stripped.lower() or "preferred" in stripped.lower():
                weak_ciphers.append(f"  [!] CIFRADO INSEGURO: {stripped}")
            continue

        # Vulnerabilidades específicas en sslscan (Heartbleed, TLS Fallback, etc.)
        if "heartbleed" in stripped.lower() and "not vulnerable" not in stripped.lower():
            vulns.append(f"  [!] {stripped}")
        elif "renegotiation" in stripped.lower() and "insecure" in stripped.lower():
            vulns.append(f"  [!] {stripped}")

        # Certificado
        if any(c in stripped.lower() for c in ("issuer:", "subject:", "not valid after:", "rsa key strength:", "signature algorithm:")):
            cert_details.append(f"  {stripped}")

    output = ["=== SSLSCAN AUDIT SUMMARY ==="]
    if protocols:
        output.append("\n[Protocolos SSL/TLS]")
        output.extend(protocols)
    if vulns:
        output.append("\n[Vulnerabilidades]")
        output.extend(vulns)
    if weak_ciphers:
        output.append("\n[Cifrados Débiles/Inseguros Detectados]")
        output.extend(weak_ciphers[:15])
    if cert_details:
        output.append("\n[Certificado SSL]")
        output.extend(cert_details)

    return "\n".join(output) if len(output) > 1 else clean_text

