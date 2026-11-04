import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

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
                temperature=0.2,
                max_tokens=7000  # Groq free tier: cap explícito para evitar corte abrupto sin señal de error
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
        # Presupuesto adaptativo: Groq free tier ~6K TPM de entrada + ~8K de salida;
        # Gemini y OpenRouter admiten ventanas masivas de tokens.
        if self.provider == "groq":
            MAX_CHARS_PER_TOOL = 3000
        else:
            MAX_CHARS_PER_TOOL = 35000

        active_tools = list(master_tool_data.keys())
        tool_count = len(active_tools)

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

        # ── INSTRUCCIÓN DE DENSIDAD (específica por proveedor) ──────────────────
        if self.provider == "groq":
            density_instruction = (
                f"\n⚠ RESTRICCIÓN DE SALIDA (proveedor Groq) ⚠\n"
                f"Se detectaron {tool_count} herramienta(s): {', '.join(active_tools)}.\n"
                f"Límite de salida ~7000 tokens. DISTRIBUCIÓN DIRECTA Y OPERATIVA:\n"
                f"  · Sección 1: breve resumen perimetral y descarte en bloque de estáticos frontend (máx 5 líneas).\n"
                f"  · Sección 2: tabla limpia obligatoria (ID / Hallazgo | Herramienta Recomendada | Metodología de Descarte Técnico | Severidad de Negocio | Riesgo Real / Impacto).\n"
                f"  · Sección 3: criterio de confirmación y descarte conceptual para cada hallazgo de la tabla.\n"
                f"  · CERO relleno académico, CERO comandos de consola, directo a la evidencia operativa.\n"
            )
        else:
            density_instruction = (
                f"\nSe detectaron {tool_count} herramienta(s): {', '.join(active_tools)}.\n"
                f"Aplica enfoque operativo de SOC: descarte de ruido frontend, metodología conceptual sin comandos y tablas limpias.\n"
            )

        system_instruction = (
            "Eres un Ingeniero de Ciberseguridad Operativa y Analista de SOC Senior.\n"
            "Tu objetivo es procesar la telemetría de herramientas de escaneo (Nmap, Katana, FFUF, Nuclei, WhatWeb, HTTPX, etc.) "
            "y generar informes de auditoría técnica limpios, directos y orientados al triaje rápido y descarte de falsos positivos en menos de 30 segundos.\n\n"

            "═══ REGLAS DE ORO OBLIGATORIAS ═══\n\n"

            "1. CERO RELLENO ACADÉMICO:\n"
            "   Queda terminantemente prohibido utilizar jerga teórica abstracta (nada de 'resumen epistémico', 'corroboración dependiente', "
            "clasificaciones vagas como 'NOT_ASSESSED' o disquisiciones filosóficas). Ve directo al grano, a la evidencia técnica y a los observables de los logs.\n\n"

            "2. ENFOQUE DE HERRAMIENTA Y METODOLOGÍA (SIN COMANDOS EXACTOS):\n"
            "   No proporciones comandos exactos de consola para copiar y pegar (prohibido escribir one-liners de curl, bash, python o scripts).\n"
            "   Para cada hallazgo u observación, debes indicar:\n"
            "   - Herramienta recomendada: La utilidad estándar de la industria para auditar ese vector (ej. Burp Suite Repeater, DevTools del navegador, OpenSSL s_client, etc.).\n"
            "   - Metodología de Descarte / Criterio Técnico: Los pasos lógicos y conceptuales que el analista debe seguir para verificar mediante razonamiento si se trata de un falso positivo o un riesgo real.\n\n"

            "3. SEPARACIÓN DE RUIDO FRONTEND / BACKEND:\n"
            "   - Agrupa y descarta rápidamente los archivos estáticos de JavaScript/CSS (bundles de frontend, chunks de webpack, estilos, imágenes) indicando claramente que son comportamiento normal de cliente.\n"
            "   - Enfoca la atención y el análisis exclusivamente en endpoints dinámicos, APIs, parámetros de entrada o servicios anómalos.\n\n"

            "4. SEVERIDAD DE NEGOCIO BASADA EN IMPACTO REAL:\n"
            "   Clasifica la severidad según el impacto real sobre la disponibilidad, operaciones o exposición de la organización:\n"
            "   - Crítico: RCE demostrado, bypass perimetral, o exposición directa de secretos maestros/bases de datos operativas.\n"
            "   - Alto: Acceso indebido a datos de negocio, manipulación de parámetros críticos o servicios administrativos expuestos sin control.\n"
            "   - Medio: Configuraciones inseguras explotables con impacto tangible en el servicio.\n"
            "   - Bajo: Ausencia de cabeceras de hardening opcionales o divulgación menor de versión sin exploit directo.\n"
            "   - Informativo: Servicios estándar expuestos por diseño o inventario perimetral normal.\n"
            "   Prohibido inflar severidades por el nombre genérico de una plantilla de escáner si no hay impacto demostrado."
        )

        # ── PROMPT ──────────────────────────────────────────────────────────────
        prompt = f"""[METADATA DEL REPORTE]
Título   : {report_title}
Objetivo : {user_query if user_query else "Triaje operativo de seguridad, descarte de falsos positivos y auditoría técnica rápida."}
{density_instruction}
[ESTRUCTURA DE SALIDA OBLIGATORIA]

# INFORME DE AUDITORÍA TÉCNICA Y TRIAJE OPERATIVO: {report_title}

## 1. Resumen Perimetral y Ruido de Frontend Descartado
- **Servicios e Infraestructura Base:** (Resumen directo de puertos, servicios y tecnologías identificadas sin alertas artificiales).
- **Ruido Frontend Descartado:** (Mención y descarte en bloque de bundles estáticos de JavaScript, CSS, fuentes o imágenes detectadas por Katana/FFUF, confirmando que representan entrega normal de interfaz cliente).

## 2. Matriz de Triaje Técnico y Descarte de Hallazgos

Presenta los resultados en una tabla limpia con las siguientes 5 columnas obligatorias exactas:

| ID / Hallazgo | Herramienta Recomendada | Metodología de Descarte Técnico (Criterio Conceptual) | Severidad de Negocio | Riesgo Real / Impacto |
|---------------|-------------------------|-------------------------------------------------------|----------------------|-----------------------|
| H-01: ...     | Burp Suite Repeater     | ...                                                   | Medio / Bajo / etc.  | ...                   |

(Si no se identifican condiciones anómalas o vulnerabilidades reales en la telemetría, indícalo expresamente en la tabla: "No se identificaron condiciones anómalas ni vulnerabilidades activas en la telemetría provista").

## 3. Metodología de Descarte Técnico y Validación Operativa
Para cada hallazgo registrado en la matriz:

### [ID] – [Nombre del Hallazgo]
- **Evidencia en Logs:** [Dato exacto y observable registrado en los artefactos provistos].
- **Herramienta Recomendada:** [Utilidad estándar para auditar este vector].
- **Metodología de Descarte (Criterio Conceptual):** [Pasos lógicos y conceptuales para verificar mediante razonamiento técnico si es falso positivo o riesgo real — SIN comandos de consola].
- **Criterio de Confirmación:** [Qué respuesta o comportamiento técnico observable del servidor probaría que el problema existe].
- **Criterio de Descarte (Falso Positivo):** [Qué respuesta técnica observable probaría que está mitigado, es regla de WAF, o es comportamiento estándar del framework].
- **Severidad de Negocio y Riesgo Real:** [Severidad asignada y justificación concisa del impacto operativo real].

[ARTEFACTOS DE ESCANEO — DATOS RECOLECTADOS POR EL ANALISTA]
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
