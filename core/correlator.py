from core.scanner import scan_target_directory
from parsers.generic_parser import parse_generic_file
from core.triage_engine import correlate_all_tools_with_gemini
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
import os

console = Console()

def run_triage_process(target_path: str, output_file: str = None, report_title: str = "Security Triage Report", provider: str = "gemini"):
    console.print(f"\n[bold cyan][TARGET][/bold cyan] Analizando estructura de directorios: [underline white]{target_path}[/underline white]")
    console.print(f"[bold cyan][TITLE][/bold cyan] Asignando nombre al reporte: [underline white]{report_title}[/underline white]")
    console.print(f"[bold cyan][PROVIDER][/bold cyan] Motor de IA seleccionado: [underline green]{provider.upper()}[/underline green]\n")
    
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
            tool_combined_content += f"\n--- File Source: {file_path} ---\n" + parse_generic_file(file_path)
        
        master_tool_content[tool_name] = tool_combined_content

    console.print("\n")
    with console.status(f"[bold magenta][AI ENGINE ({provider.upper()})][/bold magenta] Correlacionando eventos y generando tickets de findings...", spinner="bouncingBar"):
        global_correlation_result = correlate_all_tools_with_gemini(master_tool_content, report_title, provider=provider)
    
    # Validamos si el resultado es una alerta operativa o de error del proveedor
    is_operational_alert = "ALERTA OPERATIVA" in global_correlation_result or "Error" in global_correlation_result

    if is_operational_alert:
        console.print(Panel(
            f"[bold red]{global_correlation_result}[/bold red]",
            title="[bold red] ERROR / ALERTA EN MOTOR DE IA [/bold red]",
            border_style="red",
            expand=True,
            padding=(1, 2)
        ))
        console.print("\n[bold yellow][!] Operación cancelada: No se generará ningún archivo de reporte debido a restricciones del proveedor de IA.[/bold yellow]\n")
        return

    # Si todo salió bien, mostramos el reporte en consola normalmente
    panel_content = Markdown(global_correlation_result)
    console.print(Panel(
        panel_content,
        title=f"[bold white] {report_title} (by: Jay) [/bold white]",
        border_style="cyan",
        expand=True,
        padding=(1, 2)
    ))
    console.print("\n")

    # Guardamos el archivo únicamente si no hubo errores y se especificó la salida
    if output_file:
        try:
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)
                
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(global_correlation_result)
            console.print(f"[bold green][+] Reporte exportado exitosamente en:[/bold green] [underline]{output_file}[/underline]\n")
        except Exception as e:
            console.print(f"[bold red][!] Error al guardar el archivo de salida: {str(e)}[/bold red]\n")