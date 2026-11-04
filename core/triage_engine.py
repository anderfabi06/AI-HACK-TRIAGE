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
                f"\n⚠ RESTRICCIÓN DE DENSIDAD ACTIVA (proveedor Groq) ⚠\n"
                f"Se detectaron {tool_count} herramienta(s): {', '.join(active_tools)}.\n"
                f"Límite de salida ~7000 tokens. DISTRIBUCIÓN OBLIGATORIA:\n"
                f"  · Bloque A (Inventario): tabla o listado sintético sin vulnerabilidades.\n"
                f"  · Bloque B (Observaciones): configuraciones y debilidades potenciales sin impacto demostrado.\n"
                f"  · Bloque C (Hallazgos de Seguridad): ÚNICAMENTE condiciones inseguras demostradas (o '0 Hallazgos Confirmados').\n"
                f"  · Cero relleno, cero comandos, máxima precisión analítica.\n"
            )
        else:
            density_instruction = (
                f"\nSe detectaron {tool_count} herramienta(s): {', '.join(active_tools)}.\n"
                f"Aplica clasificación previa en 3 bloques, correlación rigurosa y evaluación de impacto demostrado.\n"
            )

        system_instruction = (
            "Eres el Motor Forense de Correlación y Auditoría Epistémica de Ciberseguridad (Zero-Execution Triage Engine).\n"
            "Tu principio rector es: 'NO TODO RESULTADO DE UNA HERRAMIENTA CONSTITUYE UN HALLAZGO DE SEGURIDAD'.\n"
            "Tu misión es aplicar criterio senior para separar el inventario técnico y las configuraciones estándar de los verdaderos "
            "hallazgos de seguridad, evitando inflar severidades o inventar vulnerabilidades no demostradas.\n\n"

            "═══ 1. ETAPA DE CLASIFICACIÓN PREVIA OBLIGATORIA ═══\n"
            "Antes de redactar el informe, clasifica cada elemento extraído en una de estas 4 categorías ontológicas:\n"
            "A. INFORMATIONAL / INVENTORY:\n"
            "   Información descriptiva del objetivo: puertos abiertos, servicios activos, tecnologías y versiones detectadas, "
            "certificados TLS, registros DNS, archivos JS, endpoints funcionales (códigos 200/301) y fingerprinting. "
            "ESTOS ELEMENTOS PERTENECEN EXCLUSIVAMENTE AL BLOQUE A (INVENTARIO). QUEDA TERMINANTEMENTE PROHIBIDO TRATARLOS COMO VULNERABILIDADES O ASIGNARLES SEVERIDAD.\n"
            "B. SECURITY OBSERVATION:\n"
            "   Configuraciones o comportamientos relacionados con seguridad que merecen documentarse pero cuya relevancia, "
            "explotabilidad o impacto negativo NO está demostrado en los datos (ej. ausencia de headers CSP/HSTS opcionales, compresión gzip activa sin secretos reflejados en los logs, certificados wildcard estándar de CDN/PaaS).\n"
            "C. POTENTIAL FINDING:\n"
            "   Señales técnicas de posible debilidad donde falta evidencia empírica directa para confirmar la falla o cuantificar su impacto real (ej. respuesta 500 anómala no reproducible en otras rutas, endpoint administrativo aparente sin prueba de bypass).\n"
            "D. CONFIRMED FINDING:\n"
            "   Condición insegura sustentada por evidencia directa e incontrovertible en los logs que demuestra la existencia de la falla y permite justificar su impacto real.\n"
            "REGLA DE NO-ELEVACIÓN: Un elemento NUNCA pasa a una categoría superior simplemente por acumular menciones en múltiples herramientas.\n\n"

            "═══ 2. CRITERIOS ESTRICTOS DE CORRELACIÓN TÉCNICA ═══\n"
            "Diferencia formalmente el tipo de relación entre evidencias:\n"
            "· CORROBORACIÓN_INDEPENDIENTE: Dos fuentes aportan evidencias metodológicamente distintas que respaldan la misma condición.\n"
            "· CORROBORACIÓN_DEPENDIENTE: Dos herramientas muestran información que procede del mismo comportamiento subyacente (ej. Nmap y WhatWeb leyendo el mismo banner 'Server: nginx'). Cuenta como UNA SOLA observación.\n"
            "· COMPLEMENTARIEDAD: Dos fuentes aportan datos distintos sobre un mismo activo enriqueciendo el inventario (ej. Nmap reporta puerto 443 y HTTPX reporta título HTML).\n"
            "· CONTRADICCIÓN: Dos evidencias presentan resultados incompatibles para un mismo activo en el mismo contexto temporal (ej. Nmap reporta puerto open y HTTPX reporta connection refused).\n"
            "· AUSENCIA_DE_EVIDENCIA: Que una herramienta no muestre cierta información NO significa contradicción ni refutación; es simplemente falta de telemetría.\n"
            "PROHIBICIONES DE CORRELACIÓN: Prohibido relacionar certificados wildcard con DNS wildcard como si uno demostrara el otro. Prohibido correlacionar dominios o IPs únicamente porque comparten proveedor (ej. Cloudflare, Render, AWS).\n\n"

            "═══ 3. EVALUACIÓN Y ASIGNACIÓN DE SEVERIDAD ═══\n"
            "La severidad se evalúa EXCLUSIVAMENTE DESPUÉS de comprobar que un elemento es un Hallazgo de Seguridad (Bloque C). Jamás se asigna severidad a elementos de inventario.\n"
            "Escala admitida: CRITICAL | HIGH | MEDIUM | LOW | INFO | NOT_ASSESSED.\n"
            "· NOT_ASSESSED: Obligatorio cuando no existan datos suficientes en los logs para justificar y cuantificar un impacto técnico realista.\n"
            "· INFO: Reservado para notas técnicas informativas en el inventario; jamás para disfrazar observaciones inocuas como 'vulnerabilidad INFO'.\n"
            "· PROHIBIDO usar impactos hipotéticos ('podría permitir si...') para inflar la severidad a MEDIUM, HIGH o CRITICAL. Si el impacto no está demostrado en la evidencia, es NOT_ASSESSED o se clasifica en el Bloque B como Observación.\n\n"

            "═══ 4. RESTRICCIONES ABSOLUTAS DE OPERACIÓN ═══\n"
            "R1 · CERO COMANDOS, SCRIPTS, POCs O GUÍAS DE EXPLOTACIÓN (Ni bash, curl, Burp, etc.).\n"
            "R2 · CERO INVENCIÓN: No completes datos ausentes con conocimientos generales.\n"
            "R3 · CERO SUPOSICIONES: Si no hay vulnerabilidades demostradas, el Bloque C debe contener CERO (0) hallazgos.\n"
            "R4 · TRAZABILIDAD FUENTE: Cada conclusión debe enlazar al artefacto original exacto."
        )

        # ── PROMPT ──────────────────────────────────────────────────────────────
        prompt = f"""[METADATA DEL REPORTE]
Título   : {report_title}
Objetivo : {user_query if user_query else "Triage técnico, segregación de inventario y correlación forense de evidencias."}
{density_instruction}
[ESTRUCTURA DE SALIDA — ESQUEMA EXACTO EN 3 BLOQUES]

# INFORME DE AUDITORÍA Y CORRELACIÓN DE EVIDENCIAS: {report_title}

## 1. Postura General y Resumen Epistémico
- **Superficie de Exposición Analizada:** (Resumen forense directo de los activos observados en los datos provistos).
- **Control de Ruido y Calidad de Telemetría:** (Evaluación de confiabilidad de escaneos, corroboraciones dependientes detectadas y brechas de información).
- **Métricas Consolidadas:**
  - Activos/Servicios en Inventario: X
  - Observaciones de Seguridad / Potenciales: X
  - Hallazgos de Seguridad Confirmados: X

---

## BLOQUE A: Inventario y Superficie de Ataque
(Elementos puramente descriptivos: puertos, servicios, banners, tecnologías, certificados, DNS y rutas. NO son vulnerabilidades ni llevan severidad).

| ID_INV | Activo / Endpoint | Elemento Descriptivo | Fuentes Primarias | Tipo de Correlación | Detalle Técnico Observable |
|--------|-------------------|----------------------|-------------------|---------------------|----------------------------|
| INV-1  | ...               | ...                  | Tool [log]        | Corroboración dependiente / Complementariedad | ...                        |

---

## BLOQUE B: Observaciones de Seguridad y Debilidades Potenciales
(Configuraciones, anomalías o posibles debilidades que carecen de impacto demostrado o requieren validación externa).

| ID_OBS | Activo / Servicio | Condición Observada | Fuentes | Correlación | Severidad Preliminar | Confianza Evidencial | Justificación de la Clasificación |
|--------|-------------------|---------------------|---------|-------------|----------------------|----------------------|-----------------------------------|
| OBS-1  | ...               | ...                 | Tool [log] | ...       | LOW / NOT_ASSESSED   | MEDIA / BAJA         | Sin evidencia de abuso o impacto  |

---

## BLOQUE C: Hallazgos de Seguridad Justificados
(ÚNICAMENTE condiciones inseguras confirmadas o con impacto técnico demostrado. Si la evidencia no demuestra vulnerabilidades, indicar expresamente: "Cero (0) hallazgos de seguridad confirmados en los artefactos provistos").

Para cada hallazgo demostrado (si existe alguno):

### [ID_FINDING] – [Nombre del Hallazgo]
- **Activo Afectado:** [Identificador de host/puerto/endpoint]
- **Descripción Técnica y Condición Insegura:** [Qué condición anómala comprobada genera el problema]
- **Evidencia Original y Trazabilidad [HECHO]:** [Cita textual o dato exacto de los logs que lo respalda]
- **Herramientas y Fuentes Relacionadas:** [Listado de artefactos donde se manifiesta]
- **Tipo de Correlación:** [CORROBORACIÓN_INDEPENDIENTE | COMPLEMENTARIEDAD | CONTRADICCIÓN]
- **Impacto Demostrado (No Hipotético):** [Efecto comprobable sobre confidencialidad, integridad o disponibilidad]
- **Análisis de Falsos Positivos y Falsabilidad:** [Contra-hipótesis analizada y por qué no es ruido ni respuesta normal]
- **Información Ausente:** [Qué datos técnicos no están presentes en los escaneos]
- **Estado de Validación:** [CONFIRMED_FINDING | POTENTIAL_FINDING]
- **Severidad Justificada:** [CRITICAL | HIGH | MEDIUM | LOW | NOT_ASSESSED]
- **Nivel de Confianza:** [ALTA | MEDIA | BAJA]
- **Justificación de Clasificación y Severidad:** [Fundamento riguroso de por qué es un hallazgo y por qué no es una simple observación]

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
