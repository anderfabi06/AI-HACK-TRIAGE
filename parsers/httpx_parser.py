import json
import re

def parse_httpx(content: str) -> str:
    """Parse httpx output.

    Handles both JSON (list of objects) and plain text formats.
    For JSON, extracts url, status_code, title (if present) and returns a markdown list.
    For plain text, filters out noise (e.g., 404/403) and returns cleaned lines.
    """
    # Try JSON detection – look for a leading '[' or '{'
    stripped = content.lstrip()
    if stripped.startswith('[') or stripped.startswith('{'):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Fallback to generic cleaning if not valid JSON
            data = []
        if isinstance(data, dict):
            data = [data]
        lines = []
        for entry in data:
            url = entry.get('url') or entry.get('input') or entry.get('host')
            status = entry.get('status_code') or entry.get('status')
            title = entry.get('title')
            parts = []
            if url:
                parts.append(url)
            if status:
                parts.append(str(status))
            if title:
                parts.append(title)
            lines.append(' - '.join(parts))
        return '\n'.join(lines) if lines else content
    # Plain‑text mode – keep lines that are not obvious noise
    lines = []
    for line in content.splitlines():
        line_s = line.strip()
        if not line_s:
            continue
        # Discard typical "no response" lines
        if re.search(r'\b404\b|\b403\b|\bNo response\b|\btimeout\b', line_s, re.IGNORECASE):
            continue
        lines.append(line_s)
    return '\n'.join(lines) if lines else content

