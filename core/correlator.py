import readline  # <-- Habilita el control nativo de flechas y cursor en la terminal
import re
from rich.console import Console
from rich.markdown import Markdown
from core.scanner import scan_and_load_target
from core.triage_engine import correlate_all_tools_with_gemini
from outputs.reporter import save_report_to_markdown

console = Console()

def sanitize_terminal_input(raw_input: str) -> str:
    """
    Filtra y elimina cualquier residuo de secuencia ANSI residual.
    """
    ansi_pattern = re.compile(r'(\x1b\[[0-9;]*[a-zA-Z]|\^\[\[[A-Z])')
    cleaned = ansi_pattern.sub('', raw_input)
    cleaned = cleaned.replace('^[[', '')
    return cleaned.strip()

def run_triage_process(target_path: str, output_file: str, report_title: str, provider: str, focus_query: str = None):
    console.print(f"\n[cyan][*] EXPLORING TARGET PATH:[/cyan] {target_path}")
    
    # Ingestión inteligente y reconocimiento automático de herramientas por carpetas/archivos
    master_tool_data = scan_and_load_target(target_path)
    
    for tool_name, data in master_tool_data.items():
        data_preview_len = len(data)
        console.print(f"    [+] TOOL/MODULE RECOGNIZED: [green]{tool_name.upper()}[/green] ([dim]{data_preview_len} chars parsed & cleaned[/dim])")

    if not master_tool_data:
        console.print("\n[red][!] CRITICAL ERROR: NO READABLE ARTIFACTS FOUND.[/red]\n", style="red")
        return

    # Si se especificó el objetivo por argumento CLI, se usa directamente; de lo contrario se pregunta en terminal
    user_query = ""
    if focus_query:
        user_query = sanitize_terminal_input(focus_query)
        console.print(f"\n[cyan][?] ANALYSIS OBJECTIVE / CORRELATION FOCUS:[/cyan] {user_query}")
    else:
        try:
            console.print("\n" + "─"*50)
            raw_query = input("[?] ANALYSIS OBJECTIVE / CORRELATION FOCUS > ")
            user_query = sanitize_terminal_input(raw_query)
        except (KeyboardInterrupt, EOFError):
            console.print("\n[red][!] OPERATION ABORTED BY USER.[/red]")
            return
        console.print("─"*50)

    console.print(f"\n[yellow][*] EXECUTING ASSET-CENTRIC CORRELATION ({provider.upper()})...[/yellow]")
    
    report_markdown = correlate_all_tools_with_gemini(
        master_tool_data=master_tool_data, 
        report_title=report_title, 
        user_query=user_query,
        provider=provider
    )

    console.print("\n")
    console.print(Markdown(report_markdown))
    console.print("\n" + "═"*50 + "\n")

    # Guardado a través del módulo centralizado reporter
    try:
        final_output_path = save_report_to_markdown(report_markdown, output_file)
        console.print(f"[green][+] REPORT COMPILED SUCCESSFULLY:[/green] [cyan]{final_output_path}[/cyan]\n")
    except Exception as e:
        console.print(f"\n[red][!] WRITE ERROR: {e}[/red]\n", style="red")
