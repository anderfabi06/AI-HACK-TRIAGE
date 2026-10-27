import os

def scan_target_directory(base_path: str) -> dict:
    """
    Escanea la ruta objetivo y mapea las carpetas basándose en los nombres de las herramientas.
    Retorna un diccionario: {"nmap": ["archivo1.txt", ...], "nuclei": ["archivo2.json", ...]}
    """
    tool_data = {}
    
    if not os.path.exists(base_path):
        return tool_data

    # Listar elementos en la ruta base
    try:
        entries = os.listdir(base_path)
    except Exception as e:
        print(f"[-] Error al leer el directorio: {e}")
        return tool_data

    for entry in entries:
        entry_path = os.path.join(base_path, entry)
        
        # Si es un directorio, asumimos que el nombre es la herramienta (ej: nmap, nuclei, gobuster)
        if os.path.isdir(entry_path):
            tool_name = entry.lower()
            tool_files = []
            
            for root, _, files in os.walk(entry_path):
                for file in files:
                    tool_files.append(os.path.join(root, file))
            
            if tool_files:
                tool_data[tool_name] = tool_files

    return tool_data