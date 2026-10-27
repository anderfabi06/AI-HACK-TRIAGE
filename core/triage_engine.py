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
        model_name = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
        
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
                model="openai/gpt-oss-120b",  
                messages=messages,
                temperature=0.6
            )
            return completion.choices[0].message.content
        except Exception as e:
            error_msg = str(e)
            if "413" in error_msg or "rate_limit_exceeded" in error_msg or "TPM" in error_msg:
                return "[-] ALERTA OPERATIVA: LIMITE DE TOKENS POR MINUTO (TPM) SUPERADO EN GROQ. EL PAYLOAD ES MUY GRANDE."
            return f"[-] Error en Groq: {error_msg}"

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
                model="google/gemma-4-26b-a4b-it:free",
                messages=messages
            )
            return res.choices[0].message.content
        except Exception as e:
            return f"[-] Error en OpenRouter: {str(e)}"

    def execute_correlation(self, master_tool_data: dict, report_title: str) -> str:
        formatted_payload = ""
        
        # PRE-FILTRADO INTELIGENTE: Limpiamos ruido manteniendo el balance necesario para análisis profundo
        for tool_name, content in master_tool_data.items():
            cleaned_lines = [line.strip() for line in content.splitlines() if line.strip()]
            compact_content = "\n".join(cleaned_lines)
            
            formatted_payload += f"\n[TOOL MODULE: {tool_name.upper()}]\n"
            # Asignamos un límite generoso pero seguro de 3000 caracteres por herramienta para no perder contexto técnico
            formatted_payload += compact_content[:3000]

        system_instruction = (
            "Eres un Red Teamer Senior y Security Engineer (by: Jay). "
            "Tu objetivo es realizar un triaje técnico exhaustivo, profundo y riguroso de artefactos de hacking. "
            "REGLAS OBLIGATORIAS:\n"
            "1. PROHIBIDO respuestas pobres o superficiales. Los contextos de los tickets deben ser técnicamente detallados, explicando el vector, la implicancia y la evidencia exacta.\n"
            "2. Los Criterios de Aceptación (AC) deben estructurarse de forma numerada (pasos técnicos claros de remediación y validación), no como una simple línea suelta.\n"
            "3. Genera un MÁXIMO de 5 tickets en total, priorizando los hallazgos con peso real de seguridad, asegurando que cada uno sea un ticket completo y profesional."
        )

        prompt = f"""
        [INFORMACION DEL REPORTE]
        - **Titulo Asignado:** {report_title}

        [ESTRUCTURA DE SALIDA REQUERIDA]
        Genera el informe estructurado exactamente de la siguiente forma en formato Markdown puro:

        # REPORTE DE TRIAJE & TICKETS DE FINDINGS: {report_title}
        (Autor: by: Jay)

        1. SÍNTESIS GLOBAL Y ESTADÍSTICAS DE SEVERIDAD
        - Redacta un párrafo analítico y completo que detalle el comportamiento global de la infraestructura evaluada, las tecnologías detectadas, la postura perimetral y las observaciones cruzadas entre todas las herramientas.
        - Conteo rápido de severidades (Crítico: X | Alto: X | Medio: X | Bajo: X | Informativo: X).

        2. TICKETS DE FINDINGS / ESTADO CONTROLADO
        - Desarrolla un **máximo de 5 tickets** altamente técnicos y detallados. Estructura cada uno exactamente así:
          - **Título:** [Severidad] (Descripción técnica clara del hallazgo)
          - **Contexto:** (Párrafo técnico exhaustivo explicando el comportamiento anómalo observado, el riesgo desde una perspectiva de Red Team / Seguridad Defensiva y la evidencia extraída. Debe incluir la referencia del archivo origen al final, ej. *Ref: [nikto/scan.txt]*).
          - **AC (Criterios de Aceptación):** (Lista numerada detallada con los pasos técnicos de remediación y validación requeridos para cerrar el ticket de forma segura).

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