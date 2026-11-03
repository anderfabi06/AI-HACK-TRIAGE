import os
import re
import readline  # <-- Habilita el control nativo de flechas y cursor en la terminal
from rich.console import Console
from rich.markdown import Markdown
from core.triage_engine import correlate_all_tools_with_gemini

console = Console()

def sanitize_terminal_input(raw_input: str) -> str:
    """
    Filtra y elimina cualquier residuo de secuencia ANSI residual.
    """
    ansi_pattern = re.compile(r'(\x1b\[[0-9;]*[a-zA-Z]|\^\[\[[A-Z])')
    cleaned = ansi_pattern.sub('', raw_input)
    cleaned = cleaned.replace('^[[', '')
    return cleaned.strip()

def run_triage_process(target_path: str, output_file: str, report_title: str, provider: str):
    console.print(f"\n[cyan][*] EXPLORING TARGET PATH:[/cyan] {target_path}")
    
    master_tool_data = {}
    
    if os.path.isdir(target_path):
        items = os.listdir(target_path)
        for item in items:
            item_path = os.path.join(target_path, item)
            if os.path.isfile(item_path):
                tool_name, _ = os.path.splitext(item)
                try:
                    with open(item_path, 'r', encoding='utf-8', errors='ignore') as f:
                        master_tool_data[tool_name] = f.read()
                        console.print(f"    [+] ARTIFACT LOADED: [green]{item}[/green]")
                except Exception as e:
                    console.print(f"    [!] READ ERROR {item}: {e}", style="yellow")
            
            elif os.path.isdir(item_path):
                tool_name = item
                tool_content = ""
                for subfile in os.listdir(item_path):
                    subfile_path = os.path.join(item_path, subfile)
                    if os.path.isfile(subfile_path):
                        try:
                            with open(subfile_path, 'r', encoding='utf-8', errors='ignore') as f:
                                tool_content += f"\n--- Subfile: {subfile} ---\n" + f.read()
                        except Exception as e:
                            console.print(f"    [!] SUBFILE READ ERROR {subfile}: {e}", style="yellow")
                if tool_content:
                    master_tool_data[tool_name] = tool_content
                    console.print(f"    [+] MODULE LOADED: [green]{tool_name}[/green]")

    if not master_tool_data:
        console.print("\n[red][!] CRITICAL ERROR: NO READABLE ARTIFACTS FOUND.[/red]\n", style="red")
        return

    try:
        console.print("\n" + "─"*50)
        raw_query = input("[?] ANALYSIS OBJECTIVE / CORRELATION FOCUS > ")
        user_query = sanitize_terminal_input(raw_query)
    except (KeyboardInterrupt, EOFError):
        console.print("\n[red][!] OPERATION ABORTED BY USER.[/red]")
        return
    console.print("─"*50)

    console.print(f"\n[yellow][*] EXECUTING PASSIVE CORRELATION ({provider.upper()})...[/yellow]")
    
    report_markdown = correlate_all_tools_with_gemini(
        master_tool_data=master_tool_data, 
        report_title=report_title, 
        user_query=user_query,
        provider=provider
    )

    console.print("\n")
    console.print(Markdown(report_markdown))
    console.print("\n" + "═"*50 + "\n")

    output_dir = "outputs"
    os.makedirs(output_dir, exist_ok=True)
    
    final_output_path = output_file if os.path.isabs(output_file) or "/" in output_file or "\\" in output_file else os.path.join(output_dir, output_file)
    
    try:
        with open(final_output_path, 'w', encoding='utf-8') as f:
            f.write(report_markdown)
        console.print(f"[green][+] REPORT COMPILED SUCCESSFULLY:[/green] [cyan]{final_output_path}[/cyan]\n")
    except Exception as e:
        console.print(f"\n[red][!] WRITE ERROR: {e}[/red]\n", style="red")