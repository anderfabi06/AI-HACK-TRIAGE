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
            messages = [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ]
            completion = client.chat.completions.create(
                model="openai/gpt-oss-120b",  
                messages=messages,
                temperature=0.4 # Temperatura baja para mantener rigor técnico estricto
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
        
        # PRE-FILTRADO INTELIGENTE: Limpiamos ruido manteniendo el balance para análisis profundo
        for tool_name, content in master_tool_data.items():
            cleaned_lines = [line.strip() for line in content.splitlines() if line.strip()]
            compact_content = "\n".join(cleaned_lines)
            
            formatted_payload += f"\n[TOOL MODULE: {tool_name.upper()}]\n"
            formatted_payload += compact_content[:3000]

        system_instruction = (
            "Eres un Red Teamer Senior y Security Engineer (by: Jay). "
            "Tu objetivo es realizar un análisis forense, correlación cruzada y síntesis técnica avanzada de artefactos de hacking.\n\n"
            "BASE DE DATOS DE REFERENCIA Y TAXONOMÍA DE SEVERIDAD (Úsala obligatoriamente para clasificar):\n"
            "1. SEVERIDAD ALTA:\n"
            "   - Sub-domain takeover confirmado o DNS Wildcard mal configurado permitiendo spoofing.\n"
            "   - Credenciales expuestas en texto plano, secretos o tokens API activos en repositorios/archivos.\n"
            "   - Vulnerabilidades de ejecución (RCE, SQLi, LFI/RFI) confirmadas.\n"
            "2. SEVERIDAD MEDIA:\n"
            "   - Ausencia de cabeceras de aislamiento y protección en rutas críticas de autenticación (/login, /api): COOP, COEP, CORP, X-Permitted-Cross-Domain-Policies.\n"
            "   - Compresión HTTP activa (deflate/gzip) en endpoints con datos sensibles (Riesgo potencial BREACH).\n"
            "   - Configuraciones deficientes de CORS (Access-Control-Allow-Origin: *) en servicios con sesión.\n"
            "3. SEVERIDAD BAJA:\n"
            "   - Falta de HSTS únicamente en entornos de staging o pruebas.\n"
            "   - Exposición de directorios menores o listados sin impacto crítico directo.\n"
            "4. SEVERIDAD INFORMATIVA:\n"
            "   - Divulgación de versiones o banners de software / proxy (ej. Server: nginx, x-render-origin-server, rndr-id).\n"
            "   - Puertos proxy estándar abiertos asociados a CDNs (ej. Cloudflare 2052, 2053, 2082, 8080 en estado tcpwrapped o blocked).\n"
            "   - Certificados TLS con vigencia menor a 60 días en plataformas PaaS con renovación automática.\n\n"
            "REGLAS DE ANÁLISIS:\n"
            "- Cruza la información de todas las herramientas provistas (Nmap, Nuclei, Nikto, etc.).\n"
            "- Explica las razones técnicas fundamentadas de cada hallazgo.\n"
            "- Diseña la ruta de verificación (re-test) exacta para que el operador ejecute las validaciones."
        )

        prompt = f"""
        [INFORMACION DEL REPORTE]
        - **Titulo Asignado:** {report_title}

        [ESTRUCTURA DE SALIDA REQUERIDA]
        Genera un informe analítico y técnico en formato Markdown puro estructurado exactamente así:

        # ANÁLISIS FORENSE & CORRELACIÓN DE ARTEFACTOS: {report_title}
        (Autor: by: Jay)

        1. SÍNTESIS GLOBAL & CORRELACIÓN CRUZADA
        - Análisis unificado de los artefactos. Conecta los hallazgos perimetrales (CDN/WAF) con los resultados internos de escaneo.
        - Conteo Rápido de Severidades (Crítico: X | Alto: X | Medio: X | Bajo: X | Informativo: X).

        2. HALLAZGOS TÉCNICOS & VECTOR DE IMPACTO (Basado en Taxonomía)
        - Detalla los hallazgos aplicando estrictamente la Base de Datos de Referencia anterior. Incluye el contexto técnico, la evidencia y la referencia de origen (*Ref: [herramienta/archivo.txt]*).

        3. CAMINO A VERIFICAR (RUTAS DE RE-TEST)
        - Lista los comandos operativos directos (ej. `curl -I`, re-ejecución de templates específicos de Nuclei) necesarios para validar la corrección de los puntos analizados.

        4. CONCLUSIONES DE POSTURA DE SEGURIDAD
        - Veredicto final sobre la madurez del entorno evaluado y recomendaciones estratégicas de endurecimiento (hardening).

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