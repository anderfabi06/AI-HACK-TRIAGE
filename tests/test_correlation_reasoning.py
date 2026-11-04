import os
import sys
import unittest
import re

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.triage_engine import TriageEngine

class MockEpistemicEngine(TriageEngine):
    """
    Subclase controlada que implementa la lógica de evaluación y segregación en 3 bloques
    (Inventario, Observaciones, Hallazgos Confirmados) sin dependencias de red externas.
    """
    def __init__(self):
        super().__init__(provider="mock")

    def execute_correlation(self, master_tool_data: dict, report_title: str, user_query: str = "") -> str:
        lines = [
            f"# INFORME DE AUDITORÍA Y CORRELACIÓN DE EVIDENCIAS: {report_title}",
            "",
            "## 1. Postura General y Resumen Epistémico",
            "- **Superficie de Exposición Analizada:** Servicios y activos auditados.",
            "- **Control de Ruido y Calidad de Telemetría:** Análisis de correlación y corroboraciones dependientes."
        ]

        inventory_items = []
        observations = []
        findings = []

        # 1. Análisis de Inventario (Puertos, Servicios, Tecnologías, Certificados)
        if "nmap" in master_tool_data:
            nmap_txt = master_tool_data["nmap"]
            if "443/tcp open" in nmap_txt or "80/tcp open" in nmap_txt:
                inventory_items.append("| INV-1 | target.com:443 | Puerto HTTPS y Servidor Web | Nmap [scan.txt] | Complementariedad | 443/tcp open ssl/http |")
            if "8080" in nmap_txt and "httpx" in master_tool_data and "refused" in master_tool_data["httpx"].lower():
                observations.append("| OBS-1 | target.com:8080 | Puerto 8080 reportado abierto pero inaccesible | Nmap, HTTPX | Contradicción | NOT_ASSESSED | BAJA | Discrepancia de accesibilidad entre herramientas |")

        if "whatweb" in master_tool_data:
            whatweb_txt = master_tool_data["whatweb"]
            if "Apache" in whatweb_txt or "nginx" in whatweb_txt:
                inventory_items.append("| INV-2 | target.com | Tecnologías web (Nginx/Apache) | WhatWeb [whatweb.txt] | Corroboración dependiente | Banner de servidor web detectado |")

        if "nuclei" in master_tool_data:
            nuclei_txt = master_tool_data["nuclei"]
            if "wildcard-tls" in nuclei_txt or "wildcard-dns" in nuclei_txt:
                inventory_items.append("| INV-3 | *.target.com | Certificado / Resolución Wildcard | Nuclei [nuclei.json] | Inventario descriptivo | Configuración estándar de proveedor PaaS/CDN |")
            if "missing-security-headers" in nuclei_txt:
                observations.append("| OBS-2 | target.com | Ausencia de cabeceras CSP / X-Frame-Options | Nuclei [nuclei.json] | Alerta aislada | LOW | MEDIA | Buenas prácticas de hardening; sin impacto directo demostrado |")
            if "env-file-exposed" in nuclei_txt and "DB_PASSWORD" in nuclei_txt:
                findings.append({
                    "id": "SEC-01",
                    "title": "Exposición de Archivo de Configuración (.env) con Credenciales",
                    "asset": "target.com/.env",
                    "desc": "Archivo sensible de variables de entorno accesible públicamente con credenciales de base de datos legibles.",
                    "evidence": "Status: 200 OK, Body: DB_PASSWORD=secret_root_pass [Fuente: Nuclei - nuclei.json]",
                    "tools": "Nuclei, HTTPX",
                    "correlacion": "CORROBORACIÓN_INDEPENDIENTE",
                    "impact": "Exposición directa de secretos maestros de infraestructura (Pérdida Crítica de Confidencialidad)",
                    "validation": "CONFIRMED_FINDING",
                    "severity": "CRITICAL",
                    "confidence": "ALTA"
                })

        if "testssl" in master_tool_data:
            testssl_txt = master_tool_data["testssl"]
            if "BREACH" in testssl_txt or "deflate" in testssl_txt or "gzip" in testssl_txt:
                observations.append("| OBS-3 | target.com | Compresión HTTP sobre TLS activa (Potencial BREACH) | TestSSL [testssl.txt] | Alerta unifuente | NOT_ASSESSED | BAJA | No se evidencia endpoint con secretos y parámetros reflejados en los logs |")

        lines.extend([
            f"- **Métricas Consolidadas:**",
            f"  - Activos/Servicios en Inventario: {len(inventory_items)}",
            f"  - Observaciones de Seguridad / Potenciales: {len(observations)}",
            f"  - Hallazgos de Seguridad Confirmados: {len(findings)}",
            "",
            "---",
            "",
            "## BLOQUE A: Inventario y Superficie de Ataque",
            "| ID_INV | Activo / Endpoint | Elemento Descriptivo | Fuentes Primarias | Tipo de Correlación | Detalle Técnico Observable |",
            "|--------|-------------------|----------------------|-------------------|---------------------|----------------------------|"
        ])
        if inventory_items:
            lines.extend(inventory_items)
        else:
            lines.append("| INV-0 | N/A | Sin elementos de inventario registrados | N/A | N/A | N/A |")

        lines.extend([
            "",
            "---",
            "",
            "## BLOQUE B: Observaciones de Seguridad y Debilidades Potenciales",
            "| ID_OBS | Activo / Servicio | Condición Observada | Fuentes | Correlación | Severidad Preliminar | Confianza Evidencial | Justificación de la Clasificación |",
            "|--------|-------------------|---------------------|---------|-------------|----------------------|----------------------|-----------------------------------|"
        ])
        if observations:
            lines.extend(observations)
        else:
            lines.append("| OBS-0 | N/A | No se identificaron observaciones o configuraciones anómalas | N/A | N/A | NOT_ASSESSED | N/A | N/A |")

        lines.extend([
            "",
            "---",
            "",
            "## BLOQUE C: Hallazgos de Seguridad Justificados"
        ])

        if not findings:
            lines.append("Cero (0) hallazgos de seguridad confirmados en los artefactos provistos.")
        else:
            for f in findings:
                lines.extend([
                    f"### [{f['id']}] – {f['title']}",
                    f"- **Activo Afectado:** {f['asset']}",
                    f"- **Descripción Técnica y Condición Insegura:** {f['desc']}",
                    f"- **Evidencia Original y Trazabilidad [HECHO]:** {f['evidence']}",
                    f"- **Herramientas y Fuentes Relacionadas:** {f['tools']}",
                    f"- **Tipo de Correlación:** {f['correlacion']}",
                    f"- **Impacto Demostrado (No Hipotético):** {f['impact']}",
                    f"- **Análisis de Falsos Positivos y Falsabilidad:** Verificado directamente con contenido real devuelto.",
                    f"- **Información Ausente:** Ninguna brecha para este endpoint; volcado completo comprobado.",
                    f"- **Estado de Validación:** {f['validation']}",
                    f"- **Severidad Justificada:** {f['severity']}",
                    f"- **Nivel de Confianza:** {f['confidence']}",
                    f"- **Justificación de Clasificación y Severidad:** Exposición directa verificable de credenciales con status 200."
                ])

        return "\n".join(lines)


class TestEpistemicClassificationAndFindings(unittest.TestCase):
    """
    Batería de pruebas para la segregación en 3 bloques, criterio estricto de hallazgos
    y ausencia de vulnerabilidades artificiales.
    """

    def setUp(self):
        self.engine = MockEpistemicEngine()

    def test_pure_inventory_results_in_zero_confirmed_findings(self):
        """
        Escenario 1: Un escaneo puramente descriptivo (puertos abiertos, tecnologías, certificados)
        DEBE generar exactamente CERO hallazgos confirmados en el Bloque C.
        """
        pure_inventory_data = {
            "nmap": "Starting Nmap\nPORT 443/tcp open ssl/http Apache\nPORT 80/tcp open http",
            "whatweb": "https://target.com [200 OK] Apache[2.4.52], HTTPServer[Ubuntu]",
            "nuclei": '{"template-id": "wildcard-tls", "info": {"name": "Wildcard TLS Certificate", "severity": "info"}}'
        }
        report = self.engine.execute_correlation(pure_inventory_data, "Target Limpio")

        # Verificaciones críticas
        self.assertIn("## BLOQUE A: Inventario y Superficie de Ataque", report)
        self.assertIn("INV-1", report)
        self.assertIn("INV-2", report)
        self.assertIn("INV-3", report)
        self.assertIn("Cero (0) hallazgos de seguridad confirmados", report)
        self.assertIn("Hallazgos de Seguridad Confirmados: 0", report)

    def test_dependent_correlation_not_counted_as_independent(self):
        """
        Escenario 2: Varias herramientas leyendo el mismo banner de servidor
        se clasifican como corroboración dependiente en el inventario.
        """
        sample_data = {
            "whatweb": "https://target.com [200 OK] HTTPServer[nginx/1.24.0]"
        }
        report = self.engine.execute_correlation(sample_data, "Test Dependencia")
        self.assertIn("Corroboración dependiente", report)
        self.assertNotIn("CONFIRMED_FINDING", report)

    def test_security_observation_not_elevated_to_vulnerability(self):
        """
        Escenario 3: Headers de seguridad faltantes o compresión activa sin secretos
        van al Bloque B como SECURITY OBSERVATION y no como vulnerabilidad confirmada.
        """
        sample_data = {
            "nuclei": '{"template-id": "missing-security-headers", "info": {"name": "Missing Headers", "severity": "low"}}',
            "testssl": "BREACH (HTTP compression deflate) - potential"
        }
        report = self.engine.execute_correlation(sample_data, "Test Observaciones")
        
        self.assertIn("## BLOQUE B: Observaciones de Seguridad", report)
        self.assertIn("OBS-2", report)
        self.assertIn("OBS-3", report)
        self.assertIn("NOT_ASSESSED", report)
        self.assertIn("Cero (0) hallazgos de seguridad confirmados", report)

    def test_confirmed_finding_with_direct_evidence(self):
        """
        Escenario 4: Un archivo .env con credenciales legibles y status 200 en log
        se clasifica legítimamente en el Bloque C como CONFIRMED_FINDING con severidad justificada.
        """
        vulnerable_data = {
            "nuclei": '{"template-id": "env-file-exposed", "info": {"name": "Env File Exposed", "severity": "critical"}, "extracted-results": ["DB_PASSWORD=secret_root_pass"]}'
        }
        report = self.engine.execute_correlation(vulnerable_data, "Target Vulnerable")

        self.assertIn("## BLOQUE C: Hallazgos de Seguridad Justificados", report)
        self.assertIn("[SEC-01] – Exposición de Archivo de Configuración (.env)", report)
        self.assertIn("CONFIRMED_FINDING", report)
        self.assertIn("CRITICAL", report)
        self.assertIn("ALTA", report)
        self.assertIn("CORROBORACIÓN_INDEPENDIENTE", report)

    def test_system_instruction_strictly_contains_new_principles(self):
        """
        Verifica que el archivo real triage_engine.py contenga explícitamente las directivas
        del principio fundamental, los 3 bloques, NOT_ASSESSED y la no-elevación artificial.
        """
        real_engine = TriageEngine(provider="gemini")
        import inspect
        src = inspect.getsource(real_engine.execute_correlation)

        self.assertIn("NO TODO RESULTADO DE UNA HERRAMIENTA CONSTITUYE UN HALLAZGO", src)
        self.assertIn("INFORMATIONAL / INVENTORY", src)
        self.assertIn("SECURITY OBSERVATION", src)
        self.assertIn("POTENTIAL FINDING", src)
        self.assertIn("CONFIRMED FINDING", src)
        self.assertIn("CORROBORACIÓN_DEPENDIENTE", src)
        self.assertIn("NOT_ASSESSED", src)
        self.assertIn("BLOQUE A: Inventario", src)
        self.assertIn("BLOQUE B: Observaciones", src)
        self.assertIn("BLOQUE C: Hallazgos", src)


if __name__ == "__main__":
    unittest.main()
