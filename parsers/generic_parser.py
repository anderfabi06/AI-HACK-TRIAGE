import re

def clean_ansi(text: str) -> str:
    """Elimina secuencias de escape ANSI de terminal."""
    ansi_pattern = re.compile(r'(\x1b\[[0-9;]*[a-zA-Z]|\^\[\[[A-Z])')
    return ansi_pattern.sub('', text)

def parse_generic_content(content: str) -> str:
    """
    Limpia y optimiza contenido de logs genéricos eliminando ruido,
    secuencias ANSI, barras de progreso y líneas repetitivas.
    """
    if not content:
        return ""

    content = clean_ansi(content)
    lines = content.splitlines()
    cleaned_lines = []
    
    # Expresiones regulares para filtrar ruido común
    progress_pattern = re.compile(r'(\[\s*=*>\s*\]|\d+%\s*complete|ETA:?\s*\d+)', re.IGNORECASE)
    banner_noise = re.compile(r'^[=\-_*#]{10,}$')

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        # Descartar indicadores de progreso
        if progress_pattern.search(stripped):
            continue
        # Descartar separadores visuales gigantes
        if banner_noise.match(stripped):
            continue
        cleaned_lines.append(stripped)

    # Si hay demasiadas líneas idénticas consecutivas, colapsarlas
    deduped = []
    prev_line = None
    repeat_count = 0

    for l in cleaned_lines:
        if l == prev_line:
            repeat_count += 1
            if repeat_count <= 2:
                deduped.append(l)
            elif repeat_count == 3:
                deduped.append("[... Líneas repetitivas similares omitidas ...]")
        else:
            repeat_count = 0
            deduped.append(l)
            prev_line = l

    return "\n".join(deduped)
