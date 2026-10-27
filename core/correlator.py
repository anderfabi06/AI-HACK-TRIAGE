from core.scanner import scan_target_directory
from parsers.generic_parser import parse_generic_file
from core.triage_engine import correlate_all_tools_with_gemini
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown

console = Console()

def run_triage_process(target_path: str):
    console.print(f"\n[bold cyan][TARGET][/bold cyan] Analizando estructura de directorios: [underline white]{target_path}[/underline white]")
    
    with console.status("[yellow]>[/yellow] Procesando modulos y escaneando artefactos de herramientas...", spinner="dots"):
        tool_data = scan_target_directory(target_path)
    
    if not tool_data:
        console.print("[bold red][!] Alerta: No se detectaron subcarpetas de herramientas validas en la ruta.[/bold red]")
        return

    detected = " | ".join([f"[green]{t.upper()}[/green]" for t in tool_data.keys()])
    console.print(f"[bold cyan][MODULES DETECTED][/bold cyan] {detected}\n")

    master_tool_content = {}
    for tool_name, files in tool_data.items():
        console.print(f"[dim]--------------------------------------------------------------------------------[/dim]")
        console.print(f"[bold blue][*] LEYENDO ARTEFACTOS:[/bold blue] [yellow]{tool_name.upper()}[/yellow] [dim]({len(files)} archivos)[/dim]")
        
        tool_combined_content = ""
        for file_path in files:
            console.print(f"    [dim cyan]-- Archivo:[/dim cyan] [white]{file_path}[/white]")
            tool_combined_content += f"\n--- File: {file_path} ---\n" + parse_generic_file(file_path)
        
        master_tool_content[tool_name] = tool_combined_content

    console.print("\n")
    with console.status("[bold magenta][AI ENGINE][/bold magenta] Correlacionando eventos y generando tickets de findings...", spinner="bouncingBar"):
        global_correlation_result = correlate_all_tools_with_gemini(master_tool_content)
    
    panel_content = Markdown(global_correlation_result)
    console.print(Panel(
        panel_content,
        title="[bold white] REPORTE DE TRIAJE & TICKETS DE FINDINGS (by: Jay) [/bold white]",
        border_style="cyan",
        expand=True,
        padding=(1, 2)
    ))
    console.print("\n")