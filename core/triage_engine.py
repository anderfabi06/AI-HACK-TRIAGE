import os
from google import genai
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=api_key) if api_key else None

def correlate_all_tools_with_gemini(master_tool_data: dict) -> str:
    """Realiza la correlación global, estadísticas de severidad y genera tickets independientes (Título, Contexto, AC)."""
    if not client:
        return "[-] Error: GEMINI_API_KEY no está configurada en el archivo .env"

    model_name = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
    
    formatted_payload = ""
    for tool_name, content in master_tool_data.items():
        formatted_payload += f"\n[TOOL MODULE: {tool_name.upper()}]\n"
        formatted_payload += content[:10000]

    prompt = """
    [ROL]
    Eres un Red Teamer Senior y Security Engineer (by: Jay). Tu objetivo es realizar un triaje técnico riguroso de artefactos de hacking, sintetizar los resultados, proveer estadísticas rápidas de severidad y estructurar tickets limpios sin elementos decorativos ni emojis.

    [ESTRUCTURA DE SALIDA REQUERIDA]
    Genera el informe estructurado exactamente en las siguientes secciones:

    1. SINTESIS GLOBAL Y ESTADISTICAS DE SEVERIDAD
    - Resumen técnico cruzado de lo analizado en las herramientas.
    - Conteo rápido de severidades (Critico: X | Alto: X | Medio: X | Bajo: X | Informativo: X).

    2. TICKETS DE FINDINGS / ESTADO CONTROLADO
    - Si no se encuentran vulnerabilidades reales o anomalias graves, indica un resumen de lo ejecutado y declara formalmente que todo esta controlado bajo el triaje.
    - Si existen fallos o vulnerabilidades confirmadas, genera multiples tickets/issues independientes (separados, no en un solo bloque) con este formato exacto:
      - **Titulo:** (Descriptivo y directo)
      - **Contexto:** (Explicacion tecnica del comportamiento observado y evidencia extraida)
      - **AC (Criterios de Aceptacion):** (Requerimientos de validacion y remediacion tecnica para cerrar el ticket)

    [DATOS RECOLECTADOS DE LAS HERRAMIENTAS]
    {formatted_payload}
    """

    final_prompt = prompt.replace("{formatted_payload}", formatted_payload)

    try:
        response = client.models.generate_content(
            model=model_name,
            contents=final_prompt,
        )
        return response.text
    except Exception as e:
        return f"[-] Error al comunicarse con la API de Gemini: {str(e)}"