import os
import sys
import shutil
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.scanner import scan_and_load_target
from parsers.nmap_parser import parse_nmap
from parsers.nuclei_parser import parse_nuclei
from parsers import clean_and_parse_tool_data
from outputs.reporter import save_report_to_markdown

def test_parsers():
    # 1. Test Nmap Parser
    nmap_sample = """
    Starting Nmap 7.94 ( https://nmap.org ) at 2026-11-03 12:00
    Nmap scan report for 192.168.1.50
    Host is up (0.0020s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT     STATE SERVICE VERSION
    22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
    |_ssh-hostkey: 256 ...
    443/tcp  open  ssl/http Apache httpd 2.4.52
    |_http-title: Admin Portal
    Nmap done: 1 IP address scanned in 1.45 seconds
    """
    cleaned_nmap = parse_nmap(nmap_sample)
    assert "22/tcp" in cleaned_nmap
    assert "443/tcp" in cleaned_nmap
    assert "Starting Nmap" not in cleaned_nmap
    print("[✓] Nmap Parser OK")

    # 2. Test Nuclei Parser
    nuclei_sample = (
        '{"template-id": "cve-2023-38606", "info": {"name": "OpenSSH RCE", "severity": "critical"}, "matched-at": "192.168.1.50:22"}\n'
        '{"template-id": "tech-detect", "info": {"name": "Apache Detect", "severity": "info"}, "matched-at": "https://192.168.1.50"}'
    )
    cleaned_nuclei = parse_nuclei(nuclei_sample)
    assert "[CRITICAL] OpenSSH RCE" in cleaned_nuclei
    assert "192.168.1.50:22" in cleaned_nuclei
    print("[✓] Nuclei Parser OK")

def test_scanner_and_tool_recognition():
    tmp_dir = tempfile.mkdtemp()
    try:
        # Crear carpeta de herramienta 'nmap'
        nmap_dir = os.path.join(tmp_dir, "nmap")
        os.makedirs(nmap_dir)
        with open(os.path.join(nmap_dir, "scan1.txt"), "w") as f:
            f.write("Nmap scan report for host1\nPORT 80/tcp open http\n")
        
        # Crear archivo directo de herramienta 'nuclei'
        with open(os.path.join(tmp_dir, "nuclei.json"), "w") as f:
            f.write('[{"template-id": "git-config", "info": {"name": "Git Config Exposed", "severity": "high"}, "matched-at": "http://host1/.git/config"}]')

        scanned = scan_and_load_target(tmp_dir)
        assert "nmap" in scanned
        assert "nuclei" in scanned
        assert "80/tcp open" in scanned["nmap"]
        assert "Git Config Exposed" in scanned["nuclei"]
        print("[✓] Scanner & Tool Recognition by Folder/File OK")
    finally:
        shutil.rmtree(tmp_dir)

def test_reporter():
    tmp_out = tempfile.mktemp(suffix=".md")
    saved_path = save_report_to_markdown("# Test Report", tmp_out)
    assert os.path.exists(saved_path)
    with open(saved_path) as f:
        content = f.read()
    assert content == "# Test Report"
    os.remove(saved_path)
    print("[✓] Reporter save_report_to_markdown OK")

if __name__ == "__main__":
    test_parsers()
    test_scanner_and_tool_recognition()
    test_reporter()
    print("\n[ALL TESTS PASSED SUCCESSFULLY]")
