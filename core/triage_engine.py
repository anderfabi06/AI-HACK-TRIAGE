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
        # Forzamos al modelo a ser denso desde el principio para no truncar Sección 3.
        if self.provider == "groq":
            density_instruction = (
                f"\n⚠ RESTRICCIÓN DE TOKENS ACTIVA (proveedor Groq free tier) ⚠\n"
                f"Se detectaron {tool_count} herramienta(s): {', '.join(active_tools)}.\n"
                f"Tu espacio de salida es ESTRICTAMENTE limitado a ~7000 tokens totales.\n"
                f"DISTRIBUCIÓN OBLIGATORIA:\n"
                f"  · Sección 1: máximo 5 líneas + métricas. Sin párrafos extensos.\n"
                f"  · Sección 2: tabla compacta. Celdas cortas, sin redacción extensa.\n"
                f"  · Sección 3: COMPLETA todos los hallazgos. Es la prioridad máxima.\n"
                f"    - Cada campo de cada hallazgo: máximo 2 líneas densas. Sin introducción, sin relleno.\n"
                f"    - Si debes elegir entre recortar S1/S2 o S3, recorta S1 y S2.\n"
                f"  · PROHIBIDO cerrar el informe hasta documentar el último hallazgo de la Sección 2.\n"
                f"  · PROHIBIDO escribir 'Ver hallazgo anterior' o referencias cruzadas que eludan documentar.\n"
            )
        else:
            density_instruction = (
                f"\nSe detectaron {tool_count} herramienta(s): {', '.join(active_tools)}.\n"
                f"Documenta TODOS los hallazgos en Sección 3. No cierres el informe antes.\n"
            )

        system_instruction = (
            "Eres un Analista Senior de Ciberseguridad especializado en Triage, Análisis Forense de Escaneos y Descarte de Falsos Positivos.\n"
            "Tu misión: examinar los artefactos de escaneo crudos, cuestionar las alertas automatizadas para separar el ruido de los riesgos reales, "
            "y entregar un informe técnico limpio, directo y fundamentado exclusivamente en la evidencia provista.\n\n"
            
            "═══ REGLAS ABSOLUTAS DE ANÁLISIS ═══\n\n"
            
            "R1 · FILTRO AGRESIVO DE FALSOS POSITIVOS\n"
            "  Las herramientas de terminal y escáneres (Nuclei, Nmap, etc.) suelen generar falsos positivos o alertas vacías. "
            "Tu rol analítico es evaluar si la alerta tiene sustento real en los headers, códigos de estado o respuestas técnicas provistas. "
            "Si una alerta carece de evidencia que la respalde, desarróllala explícitamente como un posible falso positivo o descártala de inmediato.\n\n"
            
            "R2 · METODOLOGÍA DE COMPROBACIÓN PRÁCTICA (CERO COMANDOS DE SHELL)\n"
            "  No escribas scripts ni comandos de terminal (curl, bash, etc.). "
            "Explica la metodología táctica: qué herramienta de interacción usar (ej. Burp Suite Repeater, Caido, navegador), "
            "qué parámetros manipular, qué cabeceras observar y qué comportamiento del servidor confirma o rechaza el hallazgo.\n\n"
            
            "R3 · CALIDAD Y CONCISIÓN (MENOS HALLAZGOS, MÁS FUNDAMENTO)\n"
            "  Prohibido inventar o rellenar el informe con múltiples hallazgos débiles o fragmentados. "
            "Consolida la información y presenta únicamente hallazgos rigurosos que estén respaldados directamente por los datos de entrada. "
            "Prefiere pocos hallazgos con alto sustento técnico a una lista larga sin fundamento.\n\n"
            
            "R4 · CERO RELLENO ACADÉMICO (SIN MITRE, SIN CWE INVENTADOS)\n"
            "  No incluyas códigos MITRE ATT&CK, taxonomías CWE teóricas ni referencias a normativas a menos que aparezcan textualmente "
            "en los archivos de entrada. Concéntrate en el comportamiento técnico observable del objetivo.\n\n"
            
            "R5 · TRAZABILIDAD ESTRICTA CON LA EVIDENCIA\n"
            "  Toda afirmación debe basarse en el contenido exacto de los logs provistos (ej. 'según el output de Nmap en el puerto X...' o 'el log de Nuclei muestra...')."
        )

        # ── PROMPT ──────────────────────────────────────────────────────────────
        prompt = f"""[METADATA DEL REPORTE]
Título   : {report_title}
Objetivo : {user_query if user_query else "Triaje analítico, descarte de falsos positivos y definición de metodología de validación."}
{density_instruction}
[ESTRUCTURA DE SALIDA — ESQUEMA EXACTO]

# INFORME TÉCNICO DE TRIAGE Y VALIDACIÓN: {report_title}

## 1. Postura de Seguridad y Confiabilidad de Datos
- **Diagnóstico macro:** (Resumen técnico directo de la superficie expuesta y calidad de la evidencia analizada).
- **Control de Ruido / Falsos Positivos:** (Evaluación de cuántas alertas de los escáneres carecen de fundamento y fueron filtradas).
- **Métricas Reales:** Crítico: X | Alto: X | Medio: X | Bajo/Info: X

## 2. Matriz Consolidada de Hallazgos Validados
| ID | Activo / Endpoint | Hallazgo / Anomalía | Herramienta Origen | Severidad Consolidada | Estado Técnico |
|----|-------------------|---------------------|--------------------|-----------------------|----------------|
| H1 | ...               | ...                 | ...                | MEDIUM                | Sospecha / En revisión |

## 3. Metodología de Comprobación y Criterios de Descarte
(Aplica un bloque detallado exclusivamente para los hallazgos consolidados que requieran validación manual. Sin relleno).

### H1 – [Nombre técnico del hallazgo]
- **Evidencia Cruda de Origen:** [Dato exacto extraído de los logs analizados que disparó la alerta]
- **Análisis de Falsos Positivos:** [Por qué la herramienta automatizada pudo dar un falso positivo y qué condición técnica real determinaría si el riesgo es verídico o descartable]
- **Metodología de Validación (Sin Shell):** [Pasos operativos con proxy o navegador para aislar el comportamiento del servicio]
- **Criterio Definitivo:**
  - *Cómo confirmar:* [Observable exacto en la respuesta del servidor que valida la vulnerabilidad]
  - *Cómo descartar (Falso Positivo):* [Observable exacto que demuestra que el sistema está mitigado o que la alerta del escáner era ruido]

(Repite este bloque único solo para los hallazgos reales adicionales, si los hay).

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
