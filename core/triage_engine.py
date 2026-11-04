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
            "Eres un Analista Senior de Ciberseguridad e Infraestructura — Zero-Execution Triage Engine.\n"
            "Tu misión: sintetizar artefactos de escaneo y entregar un informe técnico riguroso, completo y de alto impacto.\n\n"

            "═══ REGLAS ABSOLUTAS (incumplirlas invalida el informe) ═══\n\n"

            "R1 · CERO COMANDOS DE SHELL\n"
            "  No escribas ningún comando de terminal, bash, PowerShell ni one-liner.\n"
            "  En su lugar indica: qué herramienta usar, qué parámetro o función activar, qué cabecera/valor observar.\n"
            "  Correcto → 'Con Burp Suite Repeater, envía una petición GET con Accept-Encoding: gzip,deflate y observa si la respuesta incluye el header Content-Encoding: gzip junto con un cuerpo comprimido.'\n"
            "  Incorrecto → 'curl -H \"Accept-Encoding: gzip\" https://target.com/'\n\n"

            "R2 · CERO ALUCINACIONES DE CVEs / REPOSITORIOS\n"
            "  Prohibido inventar CVEs, URLs de GitHub o herramientas no mencionadas en la evidencia.\n"
            "  Si la evidencia solo detectó un banner de versión → repórtalo como Banner Grabbing (CWE-200, T1082). Sin CVE.\n"
            "  Solo cita CVEs que aparezcan textualmente en los datos de entrada (Nuclei, Nmap NSE, etc.).\n\n"

            "R3 · CONSISTENCIA DE SEVERIDAD\n"
            "  La severidad asignada en la Sección 2 (Matriz) es la fuente de verdad.\n"
            "  Úsala exactamente igual en la Sección 1 y la Sección 3. No la cambies ni contradigas.\n\n"

            "R4 · SIN REPETICIÓN DE INFORMACIÓN\n"
            "  Cada dato aparece UNA SOLA VEZ en el informe.\n"
            "  La Sección 1 da el diagnóstico macro. La Sección 2 tabula. La Sección 3 desarrolla validación y descarte.\n"
            "  No recopies en Sección 3 lo que ya está en la tabla de Sección 2.\n\n"

            "R5 · SECCIÓN 3 ES PRIORITARIA — NO LA TRUNCUES\n"
            "  DEBES completar el bloque de validación de CADA hallazgo relevante de la Sección 2 antes de cerrar.\n"
            "  Si el espacio de tokens es limitado, recorta la Sección 1 y la Sección 2, pero NUNCA la Sección 3.\n"
            "  No escribas 'Ver sección anterior', 'Similar al anterior' ni atajos. Cada hallazgo se documenta completo.\n"
            "  El informe concluye con el último hallazgo de la Sección 3. No hay Sección 4 ni tablas de resumen al final.\n\n"

            "R6 · HALLAZGOS INFO/LOW — TRATAMIENTO BREVE\n"
            "  Hallazgos de severidad LOW o INFO: solo Mecanismo + Referencia + Criterio de Descarte. Sin PoC extensa.\n"
            "  No los omitas, pero no les dediques el mismo espacio que a HIGH o CRITICAL.\n\n"

            "═══ MARCO DE SEVERIDAD ═══\n"
            "CRITICAL : RCE confirmado, bypass perimetral, secretos/DB expuestos directamente.\n"
            "HIGH      : IDOR/BOLA, inyecciones confirmadas, servicios admin críticos expuestos (RDP/SMB/DB/K8s).\n"
            "MEDIUM    : CVEs con evidencia real sin PoC trivial inmediata, compresión vulnerable (BREACH), misconfiguraciones de hardening.\n"
            "LOW/INFO  : Banner grabbing, headers de seguridad ausentes, divulgación no sensible.\n\n"

            "═══ ENFOQUE DE VALIDACIÓN (aplica a MEDIUM, HIGH, CRITICAL) ═══\n"
            "Para cada hallazgo confirma:\n"
            "  · Qué observable del servidor demuestra que la vulnerabilidad está activa.\n"
            "  · Qué observable demuestra que está mitigada o es falso positivo.\n"
            "  · Referencia oficial real (CVE, CWE, OWASP, RFC). No la inventes.\n"
        )

        # ── PROMPT ──────────────────────────────────────────────────────────────
        prompt = f"""[METADATA DEL REPORTE]
Título   : {report_title}
Objetivo : {user_query if user_query else "Triage técnico y correlación de seguridad sobre los artefactos provistos."}
{density_instruction}
[ESTRUCTURA DE SALIDA — SIGUE ESTE ESQUELETO EXACTO]

Genera el informe en Markdown usando exactamente estas 3 secciones.
No añadas secciones, subtítulos extra ni tablas de resumen fuera de este esquema.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# INFORME TÉCNICO DE TRIAGE: {report_title}

## 1. Postura de Seguridad
Diagnóstico macro en 3-5 líneas: superficie expuesta, tecnologías identificadas, madurez de hardening
y vectores de mayor riesgo. Sin repetir hallazgos individuales (eso va en Sección 2 y 3).

**Métricas:** Crítico: X | Alto: X | Medio: X | Bajo/Info: X

## 2. Matriz de Hallazgos

| ID | Activo / Servicio | Hallazgo | Herramientas | MITRE ATT&CK | Severidad |
|----|-------------------|----------|--------------|--------------|-----------|
| H1 | ...               | ...      | ...          | Txxxx        | HIGH      |
(una fila por hallazgo distinto; no hay columna Explotabilidad/KEV para mantener la tabla legible)

## 3. Validación y Descarte por Hallazgo

INSTRUCCIÓN CRÍTICA: escribe un bloque completo para CADA hallazgo HIGH/CRITICAL/MEDIUM de la Sección 2.
Para LOW/INFO: solo los campos marcados con [brief].
No cierres el informe hasta haber documentado el último hallazgo.

### H1 – [Nombre del hallazgo]
- **Mecanismo y riesgo real:** [qué falla a nivel de protocolo/componente y consecuencia práctica]
- **Referencia oficial:** [CVE-XXXX-XXXXX | CWE-XXX | OWASP ASVS X.X | RFC XXXX]  ← solo real, 0 inventados
- **Herramienta y enfoque de validación:** [qué herramienta, qué función/módulo activar, qué parámetro o cabecera enviar, qué respuesta observar — SIN comandos de shell]
- **Señal de confirmación:** [observable exacto que prueba que la vulnerabilidad existe: código HTTP, header, cuerpo, comportamiento]
- **Criterio de descarte:** [observable que prueba mitigación o falso positivo: bloqueo WAF, header ausente, respuesta neutral]  [brief para LOW/INFO]
- **Remediación:** [versión parcheada, directiva de config o referencia del fabricante]

(repite el bloque anterior para H2, H3 … hasta completar TODOS los hallazgos)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
