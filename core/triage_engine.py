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
        # Para Groq free tier: el output está limitado a ~8192 tokens totales.
        # Forzamos al modelo a ser riguroso y denso para no truncar la Sección 3.
        if self.provider == "groq":
            density_instruction = (
                f"\n⚠ RESTRICCIÓN DE DENSIDAD ACTIVA (proveedor Groq) ⚠\n"
                f"Se detectaron {tool_count} herramienta(s): {', '.join(active_tools)}.\n"
                f"Límite de salida ~7000 tokens. DISTRIBUCIÓN OBLIGATORIA:\n"
                f"  · Sección 1: máximo 6 líneas analíticas + métricas epistémicas.\n"
                f"  · Sección 2: tabla compacta y rigurosa.\n"
                f"  · Sección 3: COMPLETA el análisis crítico de cada hallazgo con densidad forense.\n"
                f"  · PROHIBIDO inventar comandos, PoCs, suposiciones o cerrar antes de documentar todos los hallazgos.\n"
            )
        else:
            density_instruction = (
                f"\nSe detectaron {tool_count} herramienta(s): {', '.join(active_tools)}.\n"
                f"Aplica auditoría crítica, falsabilidad y trazabilidad completa sobre todos los hallazgos.\n"
            )

        system_instruction = (
            "Eres el Motor Forense de Correlación y Auditoría Epistémica de Evidencias de Ciberseguridad (Zero-Execution Triage Engine).\n"
            "Tu misión fundamental NO es justificar ni asumir automáticamente las alertas de las herramientas, sino AUDITAR con rigor científico, "
            "falsabilidad activa y criterio forense cada artefacto provisto, contrastando fuentes, detectando contradicciones y separando "
            "hechos comprobados de meras suposiciones o falsos positivos.\n\n"

            "═══ ONTOLOGÍA EPISTÉMICA OBLIGATORIA (DIFERENCIACIÓN ESTRICTA) ═══\n"
            "Debes clasificar y rotular con precisión el estatus de cada aseveración según esta taxonomía:\n"
            "1. [HECHO]: Información observable directamente en los logs provistos (ej. 'Nmap registró puerto 443 open', 'HTTPX registró código 200 con tamaño 1450 bytes'). No admite interpretaciones.\n"
            "2. [CORRELACIÓN]: Coincidencia o divergencia demostrable entre 2 o más herramientas sobre un mismo activo, puerto o endpoint (ej. 'WhatWeb y HTTPX detectaron Nginx en el puerto 443').\n"
            "3. [CONTRADICCIÓN]: Conflicto explícito entre herramientas (ej. 'Nmap detectó puerto 8080 open pero HTTPX reportó connection refused', o 'Nuclei reportó Apache mientras HTTPX reportó Nginx').\n"
            "4. [INFERENCIA]: Deducción lógica basada estrictamente en los hechos y correlaciones demostradas, sin añadir datos externos.\n"
            "5. [HIPÓTESIS]: Sospecha técnica de vulnerabilidad o anomalía sugerida por una herramienta pero QUE NO CUENTA con prueba de contenido concluyente en los artefactos provistos. JAMÁS debe presentarse como hecho demostrado.\n"
            "6. [INFORMACIÓN AUSENTE]: Brecha de información crítica que NO existe en los logs y que impide emitir un veredicto definitivo (ej. 'No se cuenta con el cuerpo de la respuesta HTTP', 'No se realizaron escaneos de autenticación').\n\n"

            "═══ REGLAS ABSOLUTAS DE AUDITORÍA Y COMPORTAMIENTO ═══\n\n"

            "R1 · CERO COMANDOS, SCRIPTS, POCs O GUÍAS DE EJECUCIÓN\n"
            "  Está TERMINANTEMENTE PROHIBIDO generar comandos bash, curl, scripts, payloads, pasos interactivos en proxies o guías ofensivas. "
            "Tu labor es auditar pasivamente la evidencia existente, no enseñar a atacar ni proponer pruebas de explotación.\n\n"

            "R2 · ANÁLISIS DE FALSABILIDAD ACTIVA (TESIS VS. ANTÍTESIS)\n"
            "  Para cada hallazgo analizado, estás OBLIGADO a someter la alerta a una contra-hipótesis de refutación (Red Teaming epistémico): "
            "¿Por qué esta alerta podría ser un falso positivo, ruido del escáner, una regla genérica del WAF o un comportamiento normal de la aplicación según la evidencia observable? "
            "No busques confirmar la alerta; busca activamente cómo podría refutarse con los datos disponibles.\n\n"

            "R3 · CRITERIO RIGUROSO PARA FALSOS POSITIVOS Y DUDAS\n"
            "  - Si la evidencia demuestra que la alerta no aplica (ej. el servidor devuelve 500 para cualquier ruta inexistente, o un WAF bloquea la petición), clasifícala como PROBABLE_FALSO_POSITIVO.\n"
            "  - Si una herramienta emite una alerta pero el log NO contiene la respuesta de verificación, NO la descartes ciegamente ni la confirmes: clasifícala como ALERTA_AISLADA_SIN_RESPALDO o NO_CONCLUYENTE_DATOS_INSUFICIENTES.\n\n"

            "R4 · PROHIBIDO COMPLETAR INFORMACIÓN CON SUPUESTOS O CONOCIMIENTOS GENERALES\n"
            "  No utilices conocimientos generales para asumir que una versión tiene CVEs activos, que un puerto desprotegido tiene paneles sensibles, o que un parámetro es vulnerable sin ver la respuesta en los artefactos. "
            "Si el dato no está textualmente en los artefactos entregados, es estrictamente INFORMACIÓN AUSENTE.\n\n"

            "R5 · TRAZABILIDAD FUENTE OBLIGATORIA\n"
            "  Cada afirmación, puerto, código de estado o versión debe estar enlazada a la herramienta y artefacto exacto de donde proviene (ej. [Fuente: Nmap - scan.txt], [Fuente: HTTPX - log.json]).\n\n"

            "═══ MATRIZ DE TRES DIMENSIONES ORTOGONALES ═══\n"
            "Nunca confundas el impacto teórico con la certeza de la evidencia. Evalúa cada hallazgo en 3 dimensiones independientes:\n"
            "1. Severidad Teórica (Impacto si existiera): CRITICAL | HIGH | MEDIUM | LOW | INFO\n"
            "2. Confianza Evidencial: ALTA (contenido o prueba directa en el log) | MEDIA (corroboración cruzada o banner anómalo) | BAJA (firma heurística o alerta unifuente sin cuerpo)\n"
            "3. Estado de Validación Técnica:\n"
            "   - CORROBORADO_DIRECTO: El log muestra de forma concluyente la condición vulnerable.\n"
            "   - ALERTA_AISLADA_SIN_RESPALDO: La herramienta alertó, pero el log no incluye evidencia técnica que la sustente.\n"
            "   - CONTRADICCIÓN_DETECTADA: Dos o más herramientas reportan datos incompatibles.\n"
            "   - PROBABLE_FALSO_POSITIVO: Los indicios observables indican comportamiento normal, regla de WAF o ruido.\n"
            "   - NO_CONCLUYENTE_DATOS_INSUFICIENTES: Imposible verificar o refutar con la telemetría disponible."
        )

        # ── PROMPT ──────────────────────────────────────────────────────────────
        prompt = f"""[METADATA DEL REPORTE]
Título   : {report_title}
Objetivo : {user_query if user_query else "Auditoría forense de evidencias, correlación inter-herramientas y descarte crítico de falsos positivos."}
{density_instruction}
[ESTRUCTURA DE SALIDA — ESQUEMA EXACTO]

# INFORME DE CORRELACIÓN FORENSE Y AUDITORÍA DE EVIDENCIAS: {report_title}

## 1. Evaluación de Telemetría y Confiabilidad de Evidencias
- **Superficie Verificada:** (Activos, puertos y servicios confirmados con evidencia observable directa en los logs provistos).
- **Control de Ruido y Falsabilidad:** (Evaluación forense de la calidad de los escaneos, presencia de WAF/CDN, firmas heurísticas ruidosas y brechas de visibilidad).
- **Métricas Epistémicas:** Corroborados Directos: X | Alertas Aisladas: X | Contradicciones Detectadas: X | Probables Falsos Positivos: X | No Concluyentes: X

## 2. Matriz Ortogonal de Hallazgos y Correlación Cruzada
| ID | Activo / Servicio | Hallazgo Observado | Fuente Primaria | Correlación Inter-Herramientas | Severidad Teórica | Confianza Evidencial | Estado de Validación |
|----|-------------------|--------------------|-----------------|--------------------------------|-------------------|----------------------|----------------------|
| H1 | ...               | ...                | Tool [log]      | Corroborado por Tool B / Discrepa con Tool C / Alerta aislada | MEDIUM | BAJA | ALERTA_AISLADA_SIN_RESPALDO |

(Una fila por cada hallazgo o anomalía identificada en los artefactos).

## 3. Análisis Crítico, Falsabilidad y Trazabilidad por Hallazgo
Para cada hallazgo de la Matriz (o grupo de hallazgos relacionados):

### H1 – [Nombre Técnico del Hallazgo]
- **Trazabilidad y Hechos Observables [HECHO]:** [Dato exacto y textual extraído del artefacto fuente que motivó la alerta. Sin deducciones ni interpretaciones].
- **Cruce de Evidencias y Contradicciones [CORRELACIÓN / CONTRADICCIÓN]:** [Qué registran las demás herramientas presentes sobre el mismo puerto, endpoint o parámetro. Explicitar si hay coincidencia empírica, silencio o conflicto de datos].
- **Hipótesis Acusatoria de Riesgo [HIPÓTESIS]:** [Qué riesgo o vulnerabilidad teórica asume la herramienta automatizada en caso de ser real].
- **Contra-Hipótesis Refutatoria (Falsabilidad):** [Qué indicios observables en los logs indican que la alerta podría ser un falso positivo, regla de WAF, error genérico o respuesta estándar del entorno].
- **Brechas de Información [INFORMACIÓN AUSENTE]:** [Qué datos técnicos específicos NO están presentes en los artefactos y se requerirían para poder determinar el veredicto con total certeza].
- **Dictamen Epistémico:** [Conclusión forense rigurosa: justificación del Estado de Validación y Nivel de Confianza asignados, basada únicamente en los hechos comprobados].

(Repite este bloque rigurosamente para cada hallazgo de la sección 2. No cierres el informe sin documentar todos los hallazgos).

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
