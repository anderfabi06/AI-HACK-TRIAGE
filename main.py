import argparse
import os
import re
from core.correlator import run_triage_process
from rich.console import Console

console = Console()

BANNER = r"""[bold green]
    _    ___   _   _    _    ____ _  __   _____ ____  ___    _    ____ _____ 
   / \  |_ _| | | | |  / \  / ___| |/ /  |_   _|  _ \|_ _|  / \  / ___| ____|
  / _ \  | |  | |_| | / _ \| |   | ' /     | | | |_) || |  / _ \| |  _|  _|  
 / ___ \ | |  |  _| |/ ___ \ |___| . \     | | |  _ < | | / ___ \ |_| | |___ 
/_/   \_\___| |_| |_/_/   \_\____|_|\_\    |_| |_| \_\___/_/   \_\____|_____|
[/bold green]
[dim cyan]         [ Agentic Security Triage & Correlation Engine v2.0 | by: Jay ]         [/dim cyan]
"""

def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_-]+', '_', text)
    return text

def main():
    console.print(BANNER)
    
    parser = argparse.ArgumentParser(description="CLI de Triaje Pasivo y Correlación de Hacking con IA (Zero-Execution)")
    parser.add_argument("--path", type=str, required=True, help="Ruta de la carpeta que contiene los logs y resultados")
    parser.add_argument("--output", type=str, default=None, help="Nombre o ruta personalizada opcional para el archivo de salida")
    parser.add_argument("--title", type=str, default="Security Triage Report", help="Nombre o título personalizado para el reporte")
    parser.add_argument("--provider", type=str, default="gemini", choices=["gemini", "groq", "openrouter"], help="Proveedor de IA a utilizar")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        console.print(f"\n[bold red][!] ERROR CRITICO:[/bold red] La ruta objetivo '{args.path}' no existe.\n", style="red")
        return

    output_target = args.output
    if not output_target and args.title != "Security Triage Report":
        output_target = f"{slugify(args.title)}.md"
    elif not output_target:
        output_target = "security_triage_report.md"

    run_triage_process(
        target_path=args.path, 
        output_file=output_target, 
        report_title=args.title, 
        provider=args.provider
    )

if __name__ == "__main__":
    main()