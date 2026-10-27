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
[dim cyan]         [ Agentic Security Triage & Correlation Engine v1.0 | by: Jay ]         [/dim cyan]
"""

def slugify(text: str) -> str:
    """Convierte un título con espacios/caracteres especiales en un nombre de archivo seguro."""
    text = text.lower().strip()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_-]+', '_', text)
    return text

def main():
    console.print(BANNER)
    
    parser = argparse.ArgumentParser(description="CLI de Triaje y Correlación de Hacking con IA")
    parser.add_argument("--path", type=str, required=True, help="Ruta de la carpeta que contiene las subcarpetas de herramientas")
    parser.add_argument("--output", type=str, default=None, help="Nombre o ruta personalizada opcional para el archivo de salida")
    parser.add_argument("--title", type=str, default="Security Triage Report", help="Nombre o título personalizado para el reporte")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        console.print(f"\n[bold red][!] ERROR CRITICO:[/bold red] La ruta objetivo '{args.path}' no existe en los registros.\n", style="red")
        return

    # Si se especificó un título pero NO se especificó un --output manual, 
    # autogeneramos el nombre del archivo basado en el título (ej: "Staging Orion" -> "staging_orion.md")
    output_target = args.output
    if not output_target and args.title != "Security Triage Report":
        output_target = f"{slugify(args.title)}.md"
    elif not output_target:
        output_target = "security_triage_report.md"

    run_triage_process(args.path, output_file=output_target, report_title=args.title)

if __name__ == "__main__":
    main()