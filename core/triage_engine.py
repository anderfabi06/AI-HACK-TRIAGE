import os
from dotenv import load_dotenv

load_dotenv()

class TriageEngine:
    def __init__(self, provider: str = "gemini"):
        self.provider = provider.lower()

    def _call_gemini(self, prompt: str, system_instruction: str) -> str:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            return "[-] Error: GEMINI_API_KEY no está configurada en el archivo .env"
        
        from google import genai
        client = genai.Client(api_key=api_key)
        model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        
        # Combinamos system instruction y prompt para Gemini si es necesario
        full_content = f"[INSTRUCCIONES DE SISTEMA]\n{system_instruction}\n\n[PETICION]\n{prompt}"
        
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=full_content,
            )
            return response.text
        except Exception as e:
            error_msg = str(e)
            if "503" in error_msg or "UNAVAILABLE" in error_msg or "high demand" in error_msg:
                return "[-] ALERTA OPERATIVA: EL MODELO DE IA SE ENCUENTRA EN ALTA DEMANDA EN ESTE MOMENTO. INTENTE NUEVAMENTE EN UNOS MINUTOS."
            if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "quota" in error_msg.lower():
                return "[-] ALERTA OPERATIVA: LIMITE DE TOKENS EXCEDIDO O CUOTA AGOTADA. REDUZCA EL VOLUMEN DE LOS ARTEFACTOS."
            return f"[-] Error en Gemini: {error_msg}"

    def _call_groq(self, prompt: str, system_instruction: str) -> str:
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            return "[-] Error: GROQ_API_KEY no está configurada en el archivo .env"
        try:
            from groq import Groq
            client = Groq(api_key=api_key)
            messages = [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ]
            completion = client.chat.completions.create(
                model="openai/gpt-oss-120b",  # O el modelo rápido que prefieras en Groq (ej: llama-3.3-70b-versatile)
                messages=messages,
                temperature=0.7
            )
            return completion.choices[0].message.content
        except Exception as e:
            return f"[-] Error en Groq: {str(e)}"

    def _call_openrouter(self, prompt: str, system_instruction: str) -> str:
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            return "[-] Error: OPENROUTER_API_KEY no está configurada en el archivo .env"
        try:
            from openai import OpenAI
            client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=api_key)
            messages = [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ]
            res = client.chat.completions.create(
                model="inclusionai/ling-3.0-flash-vl:free",
                messages=messages
            )
            return res.choices[0].message.content
        except Exception as e:
            return f"[-] Error en OpenRouter: {str(e)}"

    def execute_correlation(self, master_tool_data: dict, report_title: str) -> str:
        formatted_payload = ""
        for tool_name, content in master_tool_data.items():
            formatted_payload += f"\n[TOOL MODULE: {tool_name.upper()}]\n"
            formatted_payload += content[:10000]

        system_instruction = (
            "Eres un Red Teamer Senior y Security Engineer (by: Jay). "
            "Tu objetivo es realizar un triaje técnico riguroso de artefactos de hacking, "
            "sintetizar los resultados, proveer estadísticas rápidas y estructurar tickets independientes y limpios."
        )

        prompt = f"""
        [INFORMACION DEL REPORTE]
        - **Titulo Asignado:** {report_title}

        [ESTRUCTURA DE SALIDA REQUERIDA]
        Genera el informe estructurado exactamente de la siguiente forma:

        # REPORTE DE TRIAJE: {report_title}
        (Autor: by: Jay)

        1. SINTESIS GLOBAL Y ESTADISTICAS DE SEVERIDAD
        - Resumen técnico cruzado de lo analizado en todas las herramientas para este objetivo.
        - Conteo rápido de severidades (Critico: X | Alto: X | Medio: X | Bajo: X | Informativo: X).

        2. TICKETS DE FINDINGS / ESTADO CONTROLADO
        - Si no se encuentran vulnerabilidades reales o anomalias graves, indica un resumen de lo ejecutado y declara formalmente que todo esta controlado bajo el triaje.
        - Si existen fallos o vulnerabilidades confirmadas, separa cada ticket de forma independiente usando bloques claros para que no se junten. Cada ticket debe incluir obligatoriamente:
          - **Titulo:** (Descriptivo y directo)
          - **Contexto:** (Explicacion tecnica del comportamiento observado y evidencia extraida). Incluye al final del contexto, de forma muy sutil, la referencia del archivo de origen (ej. *Ref: [nikto/scan.txt]*).
          - **AC (Criterios de Aceptacion):** (Requerimientos de validacion y remediacion tecnica para cerrar el ticket).

        [DATOS RECOLECTADOS DE LAS HERRAMIENTAS]
        {formatted_payload}
        """

        if self.provider == "groq":
            return self._call_groq(prompt, system_instruction)
        elif self.provider == "openrouter":
            return self._call_openrouter(prompt, system_instruction)
        else:
            return self._call_gemini(prompt, system_instruction)

def correlate_all_tools_with_gemini(master_tool_data: dict, report_title: str, provider: str = "gemini") -> str:
    engine = TriageEngine(provider=provider)
    return engine.execute_correlation(master_tool_data, report_title)