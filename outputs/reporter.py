import os

def save_report_to_markdown(report_content: str, filename: "triage_report.md"):
    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, filename)
    
    with open(file_path, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"[+] Reporte guardado exitosamente en: {file_path}")