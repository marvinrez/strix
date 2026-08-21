import os, json, pathlib, shutil
# (a) parsing do .env corrompe senhas com aspas
shutil.rmtree("envdir", ignore_errors=True); pathlib.Path("envdir").mkdir()
pathlib.Path("envdir/.env").write_text('CERT_PASSWORD="Ab#123""\nX_TRAILING=  valor com espaco  \n')
os.environ.pop("CERT_PASSWORD", None); os.environ.pop("X_TRAILING", None)
from nfe.config import _load_dotenv
_load_dotenv(pathlib.Path("envdir/.env"))
print('[a] .env: CERT_PASSWORD="Ab#123""  ->  lido como', repr(os.environ["CERT_PASSWORD"]),
      '(esperado \'Ab#123"\')')
print('[a] X_TRAILING ->', repr(os.environ["X_TRAILING"]))

# (b) verify_tls=false + producao: aceito sem qualquer alerta
from nfe.models import NfseParams
p = json.load(open("workdir/params.json"))
p["environment"] = "producao"
p["request"]["verify_tls"] = False
p["request"]["api_base_url_override"] = "http://api-do-atacante.example/SefinNacional"
m = NfseParams.model_validate(p)
from nfe.api_client import NfseApiClient
c = NfseApiClient(m)
print("[b] environment =", m.environment, "| verify_tls =", c.verify_tls, "| base_url =", c.base_url)
print("[b] validacao de esquema/host da URL: nenhuma  -> DPS assinada enviada em texto claro")
print("[c] retries=%d -> ate %d POSTs /nfse, sem backoff e sem chave de idempotencia"
      % (m.request.retries, m.request.retries + 1))
