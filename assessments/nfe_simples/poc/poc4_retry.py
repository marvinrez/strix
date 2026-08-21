"""PoC-4: _request() reexecuta POST /nfse (nao idempotente) quando a RESPOSTA se
perde. O servidor ja processou a nota -> emissao fiscal duplicada."""
import threading, http.server, socketserver, json
from nfe.config import load_params
from nfe.api_client import NfseApiClient

recebidas = []
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("content-length", 0)); self.rfile.read(n)
        recebidas.append(self.path)          # servidor JA processou/emitiu a nota
        self.close_connection = True          # resposta se perde na volta
        if len(recebidas) >= 2:               # 2a tentativa responde normalmente
            body = json.dumps({"nfseId": "DUPLICADA"}).encode()
            self.send_response(200); self.send_header("Content-Type","application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers()
            self.wfile.write(body); self.close_connection = False
    def log_message(self, *a): pass

class S(socketserver.TCPServer):
    allow_reuse_address = True
srv = S(("127.0.0.1", 0), H)          # porta efemera
porta = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()

params = load_params("workdir/params.json")
params.request.api_base_url_override = f"http://127.0.0.1:{porta}"   # <- http:// aceito sem validacao
params.request.verify_tls = False
params.request.retries = 1
client = NfseApiClient(params)
print("[*] base_url aceita pelo cliente:", client.base_url, " (esquema http, sem TLS, sem aviso)")
with client as api:
    try:
        r = api.emit_nfse(b"<DPS>nota-unica</DPS>")
        print("[*] retorno:", r["payload"])
    except Exception as e:
        print("[*] erro:", e)
print(f"[!] POST /nfse recebidos pelo servidor: {len(recebidas)} -> {recebidas}")
print("    a MESMA nota foi transmitida", len(recebidas), "vezes.")
srv.shutdown(); srv.server_close()
