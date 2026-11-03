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
                temperature=0.2 
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

    def execute_correlation(self, master_tool_data: dict, report_title: str, user_query: str = "") -> str:
        formatted_payload = ""
        
        for tool_name, content in master_tool_data.items():
            cleaned_lines = []
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("---"):
                    cleaned_lines.append(stripped)
            
            compact_content = "\n".join(cleaned_lines)
            formatted_payload += f"\n[TOOL MODULE: {tool_name.upper()}]\n"
            formatted_payload += compact_content[:5000]

        system_instruction = (
            "Eres un Agente Pasivo de Correlación y Triage de Ciberseguridad e Infraestructura.\n"
            "Tu rol es actuar como un motor analítico universal y directo (Zero-Execution).\n\n"
            "DIRECTRICES DE ESTILO Y REDACCIÓN:\n"
            "1. Cero relleno o explicaciones burocráticas. NUNCA menciones frases como 'según lo establecido se calificó' o similares.\n"
            "2. Justificaciones estrictamente técnicas, al grano y basadas puramente en la evidencia técnica provista.\n"
            "3. Filtra y omite por completo datos o artefactos sin impacto real de seguridad (ej. logs de inicio puros de Nmap sin puertos que no aportan valor analítico).\n"
            "4. Sé directo, conciso y de alto impacto técnico para analistas senior.\n\n"
            "MARCO DE SEVERIDAD:\n"
            "- CRITICAL: RCE, bypass global de auth, exposición masiva de datos.\n"
            "- HIGH: BOLA/IDOR, escalada de privilegios vertical, inyección directa confirmada.\n"
            "- MEDIUM: Anomalías con potencial impacto que requieren validación manual por falta de contexto completo.\n"
            "- LOW / INFO: Exposiciones menores, cabeceras faltantes o información puramente descriptiva."
        )

        prompt = f"""
        [INFORMACION DEL REPORTE]
        - **Título Asignado:** {report_title}
        - **Foco de Análisis / Objetivo:** {user_query if user_query else "Triage y correlación directa de artefactos."}

        [ESTRUCTURA DE SALIDA REQUERIDA]
        Genera un informe analítico en formato Markdown puro estructurado exactamente así:

        # INFORME DE TRIAGE Y CORRELACIÓN: {report_title}

        ## 1. Resumen ejecutivo
        - **Estado general:** (Breve, directo y enfocado en la postura de seguridad actual).
        - **Hallazgos clave:** (Puntos concretos con impacto real, descartando ruido).
        - **Limitaciones técnicas:** (Falta de endpoints, parámetros o logs faltantes).

        ## 2. Correlación de evidencias
        Presenta una tabla clara y limpia cruzando exclusivamente los artefactos que tengan relevancia operativa:
        | Herramienta | Evidencia Concreta | Análisis de Correlación |

        ## 3. Hallazgos priorizados
        Presenta una tabla limpia con los hallazgos con impacto o sospechas fundadas:
        | ID | Descripción Técnica | Activo / Endpoint | Evidencia (Ref) | Severidad | Estado |

        ## 4. Guía de validación manual (Scope & Metodología)
        - **Herramienta ideal:** (ej. Burp Suite, Caido, etc.)
        - **Scope y Parámetros:** (Endpoints o vectores a probar).
        - **Acción táctica:** (Qué probar o manipular puntualmente).
        - **Criterio de Veredicto:** (Cómo confirmar vs descartar falso positivo en 1 línea).

        ## 5. Conteo de severidades
        Crítico: X | Alto: X | Medio: X | Bajo/Info: X

        [DATOS RECOLECTADOS DE LAS HERRAMIENTAS]
        {formatted_payload}
        """

        if self.provider == "groq":
            return self._call_groq(prompt, system_instruction)
        elif self.provider == "openrouter":
            return self._call_openrouter(prompt, system_instruction)
        else:
            return self._call_gemini(prompt, system_instruction)

def correlate_all_tools_with_gemini(master_tool_data: dict, report_title: str, user_query: str = "", provider: str = "gemini") -> str:
    engine = TriageEngine(provider=provider)
    return engine.execute_correlation(master_tool_data, report_title, user_query)