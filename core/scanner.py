import os
from parsers import clean_and_parse_tool_data

def scan_and_load_target(base_path: str) -> dict:
    """
    Escanea la ruta objetivo provista por el analista y reconoce las herramientas utilizadas
    a partir del nombre de las carpetas o de los nombres de los archivos.
    
    Aplica el pre-filtrado y parseo inteligente de ruido automáticamente para cada archivo
    sin corromper estructuras de archivos JSON, JSONL o de texto plano.
    Retorna un diccionario: { "tool_name": "contenido_limpio_y_estructurado" }
    """
    master_tool_data = {}

    if not os.path.exists(base_path):
        return master_tool_data

    # Listar elementos en la ruta base
    try:
        entries = sorted(os.listdir(base_path))
    except Exception as e:
        print(f"[-] Error al leer la ruta objetivo: {e}")
        return master_tool_data

    for entry in entries:
        entry_path = os.path.join(base_path, entry)

        # Caso 1: Es una carpeta nombrada con la herramienta (ej: /nmap, /nuclei, /ffuf, /whatweb)
        if os.path.isdir(entry_path):
            tool_name = entry.lower()
            parsed_subfiles = []
            
            for root, _, files in os.walk(entry_path):
                for file in sorted(files):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            raw_text = f.read()
                            if raw_text.strip():
                                # Parsear cada archivo limpiamente por separado preservando su formato JSON o TXT
                                parsed = clean_and_parse_tool_data(tool_name, raw_text)
                                if parsed and parsed.strip():
                                    parsed_subfiles.append(parsed.strip())
                    except Exception as e:
                        print(f"    [!] Error al leer {file_path}: {e}")

            if parsed_subfiles:
                master_tool_data[tool_name] = "\n\n".join(parsed_subfiles)

        # Caso 2: Es un archivo directo en la raíz de la ruta (ej: nmap.txt, nuclei.json, ffuf.json)
        elif os.path.isfile(entry_path):
            tool_name, _ = os.path.splitext(entry)
            tool_name = tool_name.lower()
            try:
                with open(entry_path, "r", encoding="utf-8", errors="ignore") as f:
                    raw_text = f.read()
                    if raw_text.strip():
                        parsed = clean_and_parse_tool_data(tool_name, raw_text)
                        if parsed and parsed.strip():
                            master_tool_data[tool_name] = parsed.strip()
            except Exception as e:
                print(f"    [!] Error al leer archivo {entry_path}: {e}")

    return master_tool_data
