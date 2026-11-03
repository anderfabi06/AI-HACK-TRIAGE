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
            "Eres un Analista Senior de Ciberseguridad e Infraestructura (Zero-Execution Triage Engine).\n"
            "Tu misión es sintetizar artefactos y evidencias técnicas recolectadas para entregar un informe\n"
            "riguroso, conciso y de alto impacto, apto para ser presentado tanto a líderes técnicos como a gerencia.\n\n"
            "REGLAS CRÍTICAS DE CALIDAD Y ENFOQUE METODOLÓGICO:\n"
            "1. PROTOCOLO DE VALIDACIÓN FUNDAMENTADA PARA CVES Y VULNERABILIDADES VERIFICABLES:\n"
            "   - Cuando se identifique un CVE o vulnerabilidad técnica confirmable (ej. BREACH, inyecciones, fallos de compresión, desbordamientos o malas configuraciones):\n"
            "     * Explica el MECANISMO TÉCNICO: qué componente, cabecera o función provoca el fallo.\n"
            "     * Proporciona una PRUEBA DE CONCEPTO SEGURA (Safe / Non-destructive PoC): explica qué enviar tácticamente con la herramienta sugerida (curl, Burp Suite, OpenSSL) para comprobar la existencia de la falla sin riesgo de causar caídas de servicio (DoS) ni daño a los datos.\n"
            "     * Define el CRITERIO DE VEREDICTO con fundamentos dobles:\n"
            "       - Señal de Confirmación: Qué respuesta exacta (firma, cabecera, error controlado o código) demuestra que el CVE es real.\n"
            "       - Señal de Descarte: Qué respuesta (bloqueo de WAF 403, mensaje sanitizado 400, o respuesta neutral) demuestra que es un falso positivo o está mitigado.\n"
            "2. ENFOQUE PROCEDIMENTAL (Cero comandos frágiles de una línea):\n"
            "   - En lugar de forzar comandos bash de una línea propensos a fallar por WAFs o comillas, enseña al analista CÓMO realizar la prueba con la herramienta adecuada.\n"
            "3. CERO ALUCINACIONES DE CVES O REPOSITORIOS FICTICIOS:\n"
            "   - Queda TERMINANTEMENTE PROHIBIDO inventar CVEs inexistentes o URLs de GitHub ficticias.\n"
            "   - Si la evidencia de los escaneos solo detectó un banner de versión (ej. `nginx/1.31.8`), repórtalo como 'Divulgación de Información / Banner Grabbing' (CWE-200 / MITRE T1082), no inventes vulnerabilidades críticas no confirmadas.\n"
            "4. CONSISTENCIA ESTRICTA DE SEVERIDAD:\n"
            "   - La severidad de la Matriz (ej. MEDIUM) debe respetarse en todo el texto. NO agregues tablas extra al final. El reporte concluye en la Sección 3.\n\n"
            "MARCO DE SEVERIDAD:\n"
            "- CRITICAL: RCE confirmado, bypass perimetral, exposición directa de bases de datos/secretos maestros.\n"
            "- HIGH: BOLA/IDOR, inyecciones confirmadas, servicios críticos de administración expuestos a internet (RDP, SMB, DBs, K8s).\n"
            "- MEDIUM: Versiones con CVEs confirmados sin PoC trivial inmediata, falta de hardening, compresión vulnerable (BREACH), certificados wildcard en SaaS.\n"
            "- LOW / INFO: Información descriptiva, divulgación de banners de versión, cabeceras de seguridad menores ausentes."
        )

        prompt = f"""
        [INFORMACION DEL REPORTE]
        - **Título Asignado:** {report_title}
        - **Foco de Análisis / Objetivo:** {user_query if user_query else "Triage técnico sintetizado y correlación de seguridad."}

        [ESTRUCTURA DE SALIDA REQUERIDA]
        Genera un informe analítico en Markdown estructurado exactamente en las siguientes 3 secciones consolidadas (NO agregues secciones ni tablas extra al final):

        # INFORME TÉCNICO DE TRIAGE: {report_title}

        ## 1. Evaluación de Postura y Riesgo Ejecutivo
        - **Diagnóstico General:** (Síntesis técnica del nivel de exposición perimetral, vectores de ataque plausibles y madurez de la infraestructura).
        - **Métricas Consolidadas:** Crítico: X | Alto: X | Medio: X | Bajo/Info: X
        - **Vectores Clave de Atención Inmediata:** (Puntos críticos de impacto real en la continuidad o seguridad del servicio).

        ## 2. Matriz Consolidada de Hallazgos y Correlación de Activos
        Presenta una única tabla integral cruzando activos, herramientas y frameworks:
        | ID | Activo / Servicio | Hallazgo Técnico | Evidencia Cruzada | MITRE ATT&CK | Explotabilidad / KEV | Severidad |

        ## 3. Metodología de Validación Táctica, Criterios de Descarte y Remediación
        Para cada hallazgo relevante de la matriz (o grupo de hallazgos relacionados):

        ### [ID] - [Nombre del Hallazgo / CVE]
        - **Mecanismo Técnico & Impacto:** (En qué consiste la falla a nivel de protocolo/software y qué riesgo real representa en 1 o 2 líneas).
        - **Referencias Oficiales:** (CVE-ID, CWE, o boletín oficial de seguridad).
        - **Herramienta Sugerida:** (ej. curl, Burp Suite Repeater, OpenSSL s_client, Nmap NSE, dig).
        - **Validación Segura (PoC de Detección No Destructiva):** (Qué petición exacta, cabeceras o valores controlados enviar para comprobar la existencia del fallo sin arriesgar la disponibilidad).
        - **Criterio de Veredicto Fundamentado:**
          * *Confirmación:* (Respuesta, cabecera o comportamiento específico del servidor que demuestra con certeza técnica que la vulnerabilidad existe).
          * *Descarte (Falso Positivo / Mitigado):* (Respuesta del servidor o WAF que demuestra que el ataque fue neutralizado o el servicio no es vulnerable).
        - **Remediación Oficial:** (Versión mínima parcheada o directiva de configuración recomendada por el fabricante).

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
