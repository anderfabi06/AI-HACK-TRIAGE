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

    # 3. Test TestSSL Parser
    testssl_sample = """
    Start 2026-11-03 12:00
    Testing protocols via sockets except NPN+ALPN 
    SSLv2      not offered (OK)
    SSLv3      not offered (OK)
    TLS 1      offered (deprecated)
    TLS 1.1    not offered (OK)
    TLS 1.2    offered (OK)
    TLS 1.3    offered (OK)
    Testing vulnerabilities
    Heartbleed (CVE-2014-0160)                not vulnerable (OK)
    SWEET32 (CVE-2016-2183, CVE-2016-6329)    VULNERABLE (NOT ok)
    POODLE, SSL (CVE-2014-3566)               not vulnerable (OK)
    """
    cleaned_testssl = clean_and_parse_tool_data("testssl", testssl_sample)
    assert "PROTOCOLO OBSOLETO HABILITADO" in cleaned_testssl
    assert "SWEET32" in cleaned_testssl
    assert "not vulnerable (OK)" not in cleaned_testssl  # Verificamos que se filtró el ruido negativo
    print("[✓] TestSSL Parser OK")

    # 4. Test SSLScan Parser
    sslscan_sample = """
    SSL/TLS Protocols:
    SSLv3     disabled
    TLSv1.0   enabled
    TLSv1.2   enabled
    Supported Server Cipher(s):
    Accepted  TLSv1.0  128 bits  RC4-SHA (INSECURE)
    Accepted  TLSv1.2  256 bits  AES256-GCM-SHA384
    """
    cleaned_sslscan = clean_and_parse_tool_data("sslscan", sslscan_sample)
    assert "PROTOCOLO OBSOLETO" in cleaned_sslscan
    assert "CIFRADO INSEGURO" in cleaned_sslscan
    print("[✓] SSLScan Parser OK")

    # 5. Test Nikto Parser (con el caso real del usuario)
    nikto_sample = """
    - Nikto v2.6.0/
    + Target Host: orion-web-staging-umn5.onrender.com
    + Target Port: 443
    + GET /login/: Uncommon header(s) 'x-render-origin-server' found, with contents: nginx/1.31.8.
    + GET /login/: Uncommon header(s) 'rndr-id' found, with contents: f25e70c8-18a1-4012.
    + GET /login/: An alt-svc header was found which is advertising HTTP/3. The endpoint is: ':443'. Nikto cannot test HTTP/3 over QUIC. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/alt-svc: 
    + GET /login/: Cloudflare detected via cf-ray header. Recommend proxying via Burp or mitmproxy to avoid TLS fingerprint blocks. See: https://github.com/sullo/nikto/wiki/Using-a-Proxy: 
    + SSL Info:           Subject:  /CN=onrender.com
    + GET /login/: The Content-Encoding header is set to "deflate" which may mean that the server is vulnerable to the BREACH attack. See: http://breachattack.com/: 
    """
    cleaned_nikto = clean_and_parse_tool_data("nikto", nikto_sample)
    assert "nginx/1.31.8" in cleaned_nikto
    assert "Cloudflare" in cleaned_nikto
    assert "BREACH" in cleaned_nikto
    assert "rndr-id" not in cleaned_nikto  # Verificamos que se filtró el header basura
    assert "Nikto cannot test" not in cleaned_nikto
    assert "See: https://" not in cleaned_nikto
    print("[✓] Nikto Parser OK")

    # 6. Test Ffuf Parser (CLI Text & JSON)
    ffuf_cli_sample = """
    :: Method           : GET
    :: URL              : https://target.com/FUZZ
    :: Wordlist         : /usr/share/wordlists/dirb/common.txt
    ________________________________________________

    .env                    [Status: 200, Size: 342, Words: 12, Lines: 8, Duration: 25ms]
    admin                   [Status: 301, Size: 178, Words: 6, Lines: 3, Duration: 32ms]
    api/v1                  [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 30ms]
    notfound                [Status: 404, Size: 150, Words: 4, Lines: 2, Duration: 20ms]
    """
    cleaned_ffuf = clean_and_parse_tool_data("ffuf", ffuf_cli_sample)
    assert "/.env" in cleaned_ffuf
    assert "RUTA SENSIBLE" in cleaned_ffuf
    assert "/admin" in cleaned_ffuf
    assert "/notfound" not in cleaned_ffuf  # 404 filtrado
    assert ":: Wordlist" not in cleaned_ffuf  # Banner filtrado
    print("[✓] Ffuf CLI Parser OK")

    ffuf_json_sample = """{
      "commandline": "ffuf -u https://target.com/FUZZ -w wordlist.txt",
      "results": [
        {"input": {"FUZZ": ".git/config"}, "status": 200, "length": 250},
        {"input": {"FUZZ": "dashboard"}, "status": 302, "length": 180, "redirectlocation": "/login"},
        {"input": {"FUZZ": "internal"}, "status": 401, "length": 90}
      ]
    }"""
    cleaned_ffuf_json = clean_and_parse_tool_data("ffuf", ffuf_json_sample)
    assert "/.git/config" in cleaned_ffuf_json
    assert "RUTA CRÍTICA" in cleaned_ffuf_json
    assert "/dashboard" in cleaned_ffuf_json
    print("[✓] Ffuf JSON Parser OK")

    # 7. Test WhatWeb Parser (JSON & TXT)
    whatweb_json_sample = """[
      {
        "target": "https://target.com",
        "http_status": 200,
        "plugins": {
          "Apache": {"version": ["2.4.52"]},
          "PHP": {"version": ["8.1.2"]},
          "HTTPServer": {"os": ["Ubuntu Linux"], "string": ["Apache/2.4.52 (Ubuntu)"]},
          "Cloudflare": {},
          "Title": {"string": ["Test Portal"]}
        }
      }
    ]"""
    cleaned_whatweb = clean_and_parse_tool_data("whatweb", whatweb_json_sample)
    assert "Apache" in cleaned_whatweb
    assert "PHP" in cleaned_whatweb
    assert "Cloudflare" in cleaned_whatweb
    print("[✓] WhatWeb JSON Parser OK")

    whatweb_txt_sample = "https://target.com [200 OK] Apache[2.4.52], Country[US], HTTPServer[Ubuntu Linux], IP[1.2.3.4], PHP[8.1.2], Title[Portal]"
    cleaned_whatweb_txt = clean_and_parse_tool_data("whatweb", whatweb_txt_sample)
    assert "Apache[2.4.52]" in cleaned_whatweb_txt
    assert "PHP[8.1.2]" in cleaned_whatweb_txt
    print("[✓] WhatWeb TXT Parser OK")

    # 8. Test Katana Parser (JSONL & TXT)
    katana_txt_sample = """
    https://target.com/
    https://target.com/login
    https://target.com/api/v1/users?id=10
    https://target.com/style.css
    https://target.com/logo.png
    """
    cleaned_katana = clean_and_parse_tool_data("katana", katana_txt_sample)
    assert "/api/v1/users?id=10" in cleaned_katana
    assert "Vectores de Inyección" in cleaned_katana
    assert "/login" in cleaned_katana
    assert "style.css" not in cleaned_katana  # Recursos estáticos descartados
    assert "logo.png" not in cleaned_katana
    print("[✓] Katana TXT Parser OK")

    katana_jsonl_sample = """
    {"timestamp":"2026-11-04","request":{"method":"GET","endpoint":"https://target.com/admin/dashboard"},"response":{"status_code":200}}
    {"timestamp":"2026-11-04","request":{"method":"GET","endpoint":"https://target.com/api/search?q=test"},"response":{"status_code":200}}
    """
    cleaned_katana_jsonl = clean_and_parse_tool_data("katana", katana_jsonl_sample)
    assert "/admin/dashboard" in cleaned_katana_jsonl
    assert "/api/search?q=test" in cleaned_katana_jsonl
    print("[✓] Katana JSONL Parser OK")

    # 9. Test Httpx Parser (JSONL, JSON Array & TXT)
    httpx_jsonl_sample = """
    {"timestamp":"2026-11-04T12:00:00Z","url":"https://target.com","status_code":200,"title":"Home Portal","webserver":"nginx/1.24","tech":["Cloudflare","Vue.js"]}
    {"timestamp":"2026-11-04T12:00:01Z","url":"https://target.com/admin","status_code":403,"title":"Access Denied","webserver":"nginx/1.24"}
    {"timestamp":"2026-11-04T12:00:02Z","url":"https://old.target.com","status_code":301,"location":"https://target.com"}
    {"timestamp":"2026-11-04T12:00:03Z","url":"https://target.com/missing","status_code":404}
    """
    cleaned_httpx_jsonl = clean_and_parse_tool_data("httpx", httpx_jsonl_sample)
    assert "https://target.com" in cleaned_httpx_jsonl
    assert "Status: 200" in cleaned_httpx_jsonl
    assert "Home Portal" in cleaned_httpx_jsonl
    assert "Status: 403" in cleaned_httpx_jsonl
    assert "https://target.com/missing" not in cleaned_httpx_jsonl  # 404 filtrado
    print("[✓] Httpx JSONL Parser OK")

    httpx_txt_sample = """
    https://target.com [200, OK] [nginx/1.24] [Home Portal]
    https://target.com/admin [403, Forbidden] [nginx/1.24] [Forbidden]
    https://old.target.com [301, https://target.com]
    https://target.com/notfound [404, Not Found]
    """
    cleaned_httpx_txt = clean_and_parse_tool_data("httpx", httpx_txt_sample)
    assert "https://target.com" in cleaned_httpx_txt
    assert "Home Portal" in cleaned_httpx_txt
    assert "https://target.com/notfound" not in cleaned_httpx_txt  # 404 filtrado
    print("[✓] Httpx TXT Parser OK")

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
