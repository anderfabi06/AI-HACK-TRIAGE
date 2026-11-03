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
            model_name = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
            messages = [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ]
            completion = client.chat.completions.create(
                model=model_name,  
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
            model_name = os.getenv("OPENROUTER_MODEL", "google/gemini-2.0-flash-001")
            messages = [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ]
            res = client.chat.completions.create(
                model=model_name,
                messages=messages
            )
            return res.choices[0].message.content
        except Exception as e:
            return f"[-] Error en OpenRouter: {str(e)}"

    def execute_correlation(self, master_tool_data: dict, report_title: str, user_query: str = "") -> str:
        formatted_payload = ""
        # Presupuesto adaptativo: Groq tiene un límite estricto de 6,000 TPM en capa gratuita;
        # Gemini y OpenRouter admiten ventanas masivas de tokens.
        if self.provider == "groq":
            MAX_CHARS_PER_TOOL = 3500
        else:
            MAX_CHARS_PER_TOOL = 35000

        for tool_name, content in master_tool_data.items():
            cleaned_lines = []
            for line in content.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("--- Subfile:"):
                    cleaned_lines.append(stripped)
            
            compact_content = "\n".join(cleaned_lines)
            
            # Truncamiento inteligente preservando cabecera y cierre si excede el presupuesto
            if len(compact_content) > MAX_CHARS_PER_TOOL:
                head_len = int(MAX_CHARS_PER_TOOL * 0.70)
                tail_len = int(MAX_CHARS_PER_TOOL * 0.25)
                head_part = compact_content[:head_len]
                tail_part = compact_content[-tail_len:]
                omitted = len(compact_content) - (head_len + tail_len)
                compact_content = (
                    f"{head_part}\n\n"
                    f"[... NOTA: Contenido extenso pre-filtrado ({omitted} caracteres omitidos) para respetar cuota de tokens ...]\n\n"
                    f"{tail_part}"
                )

            formatted_payload += f"\n[TOOL / ARTIFACT MODULE: {tool_name.upper()}]\n"
            formatted_payload += compact_content + "\n"

        system_instruction = (
            "Eres un Agente Senior de Correlación y Triage de Ciberseguridad e Infraestructura (Zero-Execution).\n"
            "Tu objetivo es asistir a analistas de ciberseguridad e infraestructura consolidando evidencias pasivas,\n"
            "evaluando la postura de seguridad de los activos y deduplicando hallazgos sin falsos positivos.\n\n"
            "DIRECTRICES OPERATIVAS DE CIBERSEGURIDAD:\n"
            "1. ENFOQUE CENTRADO EN EL ACTIVO (Asset-Centric):\n"
            "   - Agrupa y cruza evidencias por Activo (IP, FQDN/Host, Subred o Endpoint).\n"
            "   - Correlaciona los puertos y servicios expuestos (ej. Nmap) con las vulnerabilidades y peticiones web (ej. Nuclei/fuzzers).\n"
            "2. FRAMEWORKS Y AMENAZAS REALES:\n"
            "   - Mapea los hallazgos a técnicas de MITRE ATT&CK (ej. T1190 Exploit Public-Facing Application, T1046 Network Service Discovery, T1078 Valid Accounts, etc.).\n"
            "   - Evalúa la explotabilidad real y si el hallazgo cuenta con PoC pública conocida o presencia en CISA KEV (Known Exploited Vulnerabilities).\n"
            "3. VIGILANCIA DE INFRAESTRUCTURA CRÍTICA:\n"
            "   - Alerta con alta prioridad sobre exposición perimetral de servicios administrativos o de infraestructura (RDP 3389, SMB 445, SSH 22 desactualizado, WinRM, Bases de Datos 3306/5432/1433/27017, Kubernetes API 6443, consolas/paneles expuestos sin MFA).\n"
            "4. ESTILO Y REDACCIÓN:\n"
            "   - Cero relleno burocrático. Justificaciones puramente técnicas basadas en la evidencia recolectada.\n"
            "   - Descarta ruido técnico sin impacto (ej. certificados válidos estándar o puertos cerrados).\n\n"
            "MARCO DE SEVERIDAD ESTRICTA:\n"
            "- CRITICAL: RCE confirmado, bypass de autenticación en infraestructura perimetral, exposición masiva de bases de datos o secretos críticos.\n"
            "- HIGH: BOLA/IDOR, escalada de privilegios vertical, inyecciones confirmadas (SQLi/Command Injection), servicios administrativos críticos expuestos a internet (RDP/SMB/DB).\n"
            "- MEDIUM: Anomalías con potencial impacto, versiones de software con CVEs conocidos pero sin PoC trivial confirmada, falta de configuraciones de hardening.\n"
            "- LOW / INFO: Exposiciones menores, cabeceras faltantes o información puramente descriptiva de puertos/tecnologías."
        )

        prompt = f"""
        [INFORMACION DEL REPORTE]
        - **Título Asignado:** {report_title}
        - **Foco de Análisis / Objetivo:** {user_query if user_query else "Triage integral y correlación centrada en activos e infraestructura."}

        [ESTRUCTURA DE SALIDA REQUERIDA]
        Genera un informe analítico en formato Markdown estructurado exactamente de la siguiente manera:

        # INFORME DE TRIAGE Y CORRELACIÓN: {report_title}

        ## 1. Resumen Ejecutivo
        - **Postura General:** (Evaluación concisa del nivel de exposición y riesgo del entorno analizado).
        - **Vectores de Mayor Impacto:** (Los 2 o 3 hallazgos con riesgo real de compromiso inmediato).
        - **Limitaciones de Evidencia:** (Gaps de visibilidad, herramientas faltantes o escaneos incompletos).

        ## 2. Superficie de Ataque y Correlación por Activo (Asset-Centric)
        Presenta una tabla consolidando los activos identificados y sus evidencias cruzadas:
        | Activo (IP / Hostname) | Puertos y Servicios Detectados | Detecciones / Hallazgos Cruzados | Nivel de Riesgo del Activo |

        ## 3. Hallazgos Priorizados (MITRE ATT&CK & Explotabilidad)
        Presenta la tabla con los hallazgos validados o sospechas fundadas:
        | ID | Descripción Técnica | Activo Afectado | MITRE ATT&CK | Explotabilidad / KEV | Severidad | Estado |

        ## 4. Auditoría de Infraestructura y Servicios Críticos Expuestos
        - **Servicios Administrativos / Bases de Datos:** (Revisión de exposición de RDP, SSH, SMB, DBs, paneles de gestión).
        - **Configuraciones Débiles / Hardening:** (Versiones obsoletas, cifrados débiles o falta de segmentación).

        ## 5. Guía de Validación Táctica (Manual Verification & PoC)
        - **Herramienta ideal:** (ej. Burp Suite, Nmap NSE, curl, Caido).
        - **Scope y Parámetros:** (Endpoints, puertos o parámetros exactos a testear).
        - **Acción táctica:** (Payload o prueba concreta sin afectar la disponibilidad).
        - **Criterio de Veredicto:** (Cómo confirmar vulnerabilidad vs descartar falso positivo en 1 línea).

        ## 6. Conteo de Severidades
        Crítico: X | Alto: X | Medio: X | Bajo/Info: X

        [DATOS RECOLECTADOS DE LAS HERRAMIENTAS GUARDADAS POR EL ANALISTA]
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
