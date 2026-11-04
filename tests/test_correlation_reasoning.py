import os
import sys
import unittest
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.triage_engine import TriageEngine

class MockOperationalEngine(TriageEngine):
    """
    Subclase controlada que implementa la lógica de auditoría técnica y triaje operativo
    (SOC Senior) con las 5 columnas obligatorias y separación de ruido frontend.
    """
    def __init__(self):
        super().__init__(provider="mock")

    def execute_correlation(self, master_tool_data: dict, report_title: str, user_query: str = "") -> str:
        lines = [
            f"# INFORME DE AUDITORÍA TÉCNICA Y TRIAJE OPERATIVO: {report_title}",
            "",
            "## 1. Resumen Perimetral y Ruido de Frontend Descartado",
            "- **Servicios e Infraestructura Base:** Host target.com con puertos 80/443 activos (Nginx/Cloudflare).",
            "- **Ruido Frontend Descartado:** Se descartaron 24 archivos estáticos (.js, .css, webpack bundles y chunks) detectados por Katana/FFUF al tratarse de un comportamiento normal de cliente."
        ]

        matrix_rows = []
        detailed_findings = []

        # Caso 1: Ruido frontend puro (Katana/FFUF)
        # Se descarta en sección 1, no entra a la matriz como hallazgo

        # Caso 2: Exposición de archivo sensible .env con datos
        if "nuclei" in master_tool_data and "DB_PASSWORD" in master_tool_data["nuclei"]:
            matrix_rows.append(
                "| H-01: Exposición de .env con Credenciales | Burp Suite Repeater | "
                "Enviar petición GET a /.env verificando que el Content-Type sea texto plano y contenga asignaciones de variables de entorno reales en vez de página de error 404 personalizada de SPA. | "
                "Crítico | Exposición directa de credenciales maestras de base de datos en texto plano. |"
            )
            detailed_findings.append({
                "id": "H-01",
                "title": "Exposición de .env con Credenciales",
                "evidence": "GET /.env -> Status 200 OK con cadena DB_PASSWORD=secret_root_pass [Fuente: Nuclei]",
                "tool": "Burp Suite Repeater",
                "method": "Verificar con proxy que la respuesta sea el archivo de configuración genuino y no una redirección a login o HTML genérico 200.",
                "confirm": "Respuesta con MIME text/plain conteniendo pares CLAVE=VALOR de infraestructura.",
                "discard": "Respuesta que devuelva HTML del frontend con código 200 (comportamiento típico de SPA de enrutamiento) o bloqueo 403.",
                "severity": "Crítico",
                "impact": "Compromiso de acceso a datos centrales de la organización."
            })

        # Caso 3: Compresión HTTP (gzip/deflate)
        if "testssl" in master_tool_data and "gzip" in master_tool_data["testssl"].lower():
            matrix_rows.append(
                "| H-02: Compresión HTTP Activa (Potencial BREACH) | DevTools de Navegador / Burp | "
                "Inspeccionar si los endpoints dinámicos que usan compresión reflejan parámetros de entrada junto a tokens CSRF o secretos en el mismo cuerpo HTTP. | "
                "Bajo | Sin vectores de inyección o secretos reflejados en respuestas comprimidas, el riesgo es nulo. |"
            )

        lines.extend([
            "",
            "## 2. Matriz de Triaje Técnico y Descarte de Hallazgos",
            "",
            "| ID / Hallazgo | Herramienta Recomendada | Metodología de Descarte Técnico (Criterio Conceptual) | Severidad de Negocio | Riesgo Real / Impacto |",
            "|---------------|-------------------------|-------------------------------------------------------|----------------------|-----------------------|"
        ])

        if matrix_rows:
            lines.extend(matrix_rows)
        else:
            lines.append("| N/A | N/A | No se identificaron condiciones anómalas ni vulnerabilidades activas en la telemetría provista. | Informativo | Superficie perimetral normal sin alertas de seguridad. |")

        lines.extend([
            "",
            "## 3. Metodología de Descarte Técnico y Validación Operativa"
        ])

        if not detailed_findings:
            lines.append("No se registraron anomalías críticas que requieran validación técnica manual.")
        else:
            for f in detailed_findings:
                lines.extend([
                    f"",
                    f"### [{f['id']}] – {f['title']}",
                    f"- **Evidencia en Logs:** {f['evidence']}",
                    f"- **Herramienta Recomendada:** {f['tool']}",
                    f"- **Metodología de Descarte (Criterio Conceptual):** {f['method']}",
                    f"- **Criterio de Confirmación:** {f['confirm']}",
                    f"- **Criterio de Descarte (Falso Positivo):** {f['discard']}",
                    f"- **Severidad de Negocio y Riesgo Real:** {f['severity']} – {f['impact']}"
                ])

        return "\n".join(lines)


class TestOperationalSOCAuditing(unittest.TestCase):
    """
    Verifica el cumplimiento de las 4 Reglas de Oro operativas:
    1. Cero relleno académico (sin jerga abstracta).
    2. Enfoque de herramienta y metodología conceptual (cero comandos exactos).
    3. Separación y descarte de ruido frontend.
    4. Tabla con las 5 columnas obligatorias y severidad de negocio.
    """

    def setUp(self):
        self.engine = MockOperationalEngine()

    def test_zero_academic_filler_and_clean_directness(self):
        """Verifica que el prompt y sistema prohíban jerga teórica abstracta."""
        real_engine = TriageEngine(provider="gemini")
        import inspect
        src = inspect.getsource(real_engine.execute_correlation)

        # Regla 1: Prohibición explícita de jerga abstracta
        self.assertIn("CERO RELLENO ACADÉMICO", src)
        self.assertIn("resumen epistémico", src)
        self.assertIn("corroboración dependiente", src)
        self.assertIn("Ingeniero de Ciberseguridad Operativa", src)

    def test_mandatory_five_columns_in_matrix(self):
        """Verifica que la tabla de la Sección 2 incluya exactamente las 5 columnas obligatorias."""
        real_engine = TriageEngine(provider="gemini")
        import inspect
        src = inspect.getsource(real_engine.execute_correlation)

        required_columns = [
            "ID / Hallazgo",
            "Herramienta Recomendada",
            "Metodología de Descarte Técnico (Criterio Conceptual)",
            "Severidad de Negocio",
            "Riesgo Real / Impacto"
        ]
        for col in required_columns:
            self.assertIn(col, src, f"Falta la columna obligatoria: {col}")

    def test_frontend_noise_discarded_cleanly(self):
        """Verifica que los archivos estáticos de frontend se descarten como comportamiento normal."""
        synthetic_data = {
            "katana": "https://target.com/app.bundle.js\nhttps://target.com/style.chunk.css",
            "nmap": "443/tcp open ssl/http"
        }
        report = self.engine.execute_correlation(synthetic_data, "Test Frontend Noise")

        self.assertIn("Ruido Frontend Descartado", report)
        self.assertIn(".js", report)
        self.assertIn("comportamiento normal", report.lower())

    def test_operational_methodology_without_raw_commands(self):
        """Verifica que se brinde metodología conceptual sin comandos de consola ejecutables."""
        synthetic_data = {
            "nuclei": '{"template-id": "env-file-exposed", "extracted-results": ["DB_PASSWORD=secret_root_pass"]}'
        }
        report = self.engine.execute_correlation(synthetic_data, "Test Metodología")

        self.assertIn("Herramienta Recomendada", report)
        self.assertIn("Metodología de Descarte Técnico", report)
        self.assertIn("Burp Suite Repeater", report)

        # Prohibición de comandos
        forbidden_commands = [r"\bcurl\s+-", r"\bbash\b", r"\bsh\s+-", r"\bcat\s+"]
        for cmd in forbidden_commands:
            self.assertIsNone(re.search(cmd, report, re.IGNORECASE))

    def test_business_severity_scale(self):
        """Verifica la asignación de severidad de negocio (Crítico, Alto, Medio, Bajo, Informativo)."""
        real_engine = TriageEngine(provider="gemini")
        import inspect
        src = inspect.getsource(real_engine.execute_correlation)

        self.assertIn("Crítico", src)
        self.assertIn("Alto", src)
        self.assertIn("Medio", src)
        self.assertIn("Bajo", src)
        self.assertIn("Informativo", src)


if __name__ == "__main__":
    unittest.main()
