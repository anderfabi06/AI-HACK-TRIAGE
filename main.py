import argparse
import os
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

def main():
    console.print(BANNER)
    
    parser = argparse.ArgumentParser(description="CLI de Triaje y Correlación de Hacking con IA")
    parser.add_argument("--path", type=str, required=True, help="Ruta de la carpeta que contiene las subcarpetas de herramientas")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        console.print(f"\n[bold red][!] ERROR CRITICO:[/bold red] La ruta objetivo '{args.path}' no existe en el sistema.\n", style="red")
        return

    run_triage_process(args.path)

if __name__ == "__main__":
    main()