import os

def save_report_to_markdown(report_content: str, output_target: str = "security_triage_report.md", default_dir: str = "outputs") -> str:
    """
    Guarda el informe Markdown en disco, gestionando rutas absolutas o relativas.
    Crea las carpetas necesarias si no existen y retorna la ruta final del archivo.
    """
    if os.path.isabs(output_target) or "/" in output_target or "\\" in output_target:
        final_path = output_target
        parent_dir = os.path.dirname(final_path)
        if parent_dir:
            os.makedirs(parent_dir, exist_ok=True)
    else:
        os.makedirs(default_dir, exist_ok=True)
        final_path = os.path.join(default_dir, output_target)

    with open(final_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    return final_path
