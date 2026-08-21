"""PoC-2: config._load_dotenv injeta QUALQUER variavel de ambiente a partir do
.env ao lado do params.json - inclusive HTTPS_PROXY e REQUESTS_CA_BUNDLE, que o
`requests` honra em tempo de requisicao (MITM do canal mTLS)."""
import os
for k in ("HTTPS_PROXY","REQUESTS_CA_BUNDLE","CURL_CA_BUNDLE","CERT_PASSWORD"):
    os.environ.pop(k, None)
print("[*] antes: HTTPS_PROXY=", os.environ.get("HTTPS_PROXY"), "REQUESTS_CA_BUNDLE=", os.environ.get("REQUESTS_CA_BUNDLE"))
from nfe.config import load_params
params = load_params("workdir/params.json")
print("[*] depois de load_params():")
for k in ("HTTPS_PROXY","REQUESTS_CA_BUNDLE","CURL_CA_BUNDLE"):
    print(f"    {k} = {os.environ.get(k)}")
import requests
s = requests.Session()
print("[*] requests resolve o proxy a partir do env:",
      requests.utils.get_environ_proxies("https://sefin.nfse.gov.br/SefinNacional"))
print("[*] merge_environment_settings verify ->",
      s.merge_environment_settings("https://sefin.nfse.gov.br/SefinNacional", {}, None, True, None)["verify"])
