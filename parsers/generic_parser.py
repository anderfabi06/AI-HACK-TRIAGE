import json
import os

def parse_generic_file(file_path: str) -> str:
    """Lee archivos de texto, json o html de forma genérica para extraer su contenido."""
    if not os.path.exists(file_path):
        return ""
    
    try:
        if file_path.endswith('.json'):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = json.load(f)
                return json.dumps(data, indent=2)
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Si es muy pesado, limitamos o leemos completo
                return f.read()
    except Exception as e:
        return f"[-] Error leyendo {file_path}: {str(e)}"