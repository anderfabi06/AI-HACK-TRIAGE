import re
from .nmap_parser import parse_nmap
from .nuclei_parser import parse_nuclei
from .ssl_parser import parse_testssl, parse_sslscan
from .generic_parser import parse_generic_content

def parse_web_discovery(content: str) -> str:
    """Filtra salidas de Gobuster, Ffuf, Dirsearch descartando respuestas 404/400 ruidosas."""
    lines = content.splitlines()
    filtered = []
    
    for line in lines:
        line_s = line.strip()
        if not line_s:
            continue
        # Descartar códigos 404 o códigos de no encontrado
        if re.search(r'(Status:\s*404|\[404\]|\b404\b)', line_s):
            continue
        # Descartar banners repetitivos de inicio
        if line_s.startswith("====") or "Starting gobuster" in line_s or ":: Method" in line_s:
            continue
        filtered.append(line_s)
        
    return "\n".join(filtered) if filtered else content

def clean_and_parse_tool_data(tool_name: str, content: str) -> str:
    """
    Despacha el contenido al parser correspondiente basándose en el nombre
    de la carpeta o archivo de la herramienta registrada por el analista.
    """
    t_name = tool_name.lower()
    
    if "nmap" in t_name or "masscan" in t_name:
        return parse_nmap(content)
    elif "nuclei" in t_name:
        return parse_nuclei(content)
    elif "testssl" in t_name:
        return parse_testssl(content)
    elif "sslscan" in t_name:
        return parse_sslscan(content)
    elif any(fuzz in t_name for fuzz in ("gobuster", "ffuf", "dirsearch", "dirb", "feroxbuster")):
        return parse_web_discovery(content)
    else:
        return parse_generic_content(content)
