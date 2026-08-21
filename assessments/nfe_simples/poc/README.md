# PoCs — `danielcarletti/nfe_simples`

Provas de conceito dos achados descritos em [`../README.md`](../README.md). Todos rodam
localmente, com certificados auto-assinados gerados na hora. **Nenhum toca a API da SEFIN.**

```bash
git clone https://github.com/danielcarletti/nfe_simples
cd nfe_simples && pip install -e ".[dev]"
cp -r /caminho/para/assessments/nfe_simples/poc . && cd poc

python setup_fixtures.py     # gera os .pfx, o workdir/params.json e o .env do PoC-2

python poc1_aia.py           # #2 — SSRF e file:// no download da cadeia AIA
python poc3_disk.py          # #5 — chave em claro em /tmp + saídas 0644
python poc4_retry.py         # #4 — POST retentado → nota duplicada
python poc5_misc.py          # #3 e #8 — TLS desligado, http:// aceito, parsing do .env
python poc6_xml.py           # #6 — resultado negativo (XXE não explorável hoje)

# o PoC-2 precisa de ambiente sem proxy herdado:
env -i PATH="$PATH" PYTHONPATH="$PWD/../src" python poc2_dotenv.py   # #1 — MITM via .env
```

| Arquivo | Achado |
| --- | --- |
| `setup_fixtures.py` | prepara os artefatos usados pelos demais |
| `mkcert.py` | gera um `.pfx` de teste com AIA CA_ISSUERS controlado |
| `poc1_aia.py` | #2 — SSRF / leitura local via AIA |
| `poc2_dotenv.py` | #1 — injeção de variável de ambiente via `.env` |
| `poc3_disk.py` | #5 — material sensível em disco |
| `poc4_retry.py` | #4 — emissão fiscal duplicada |
| `poc5_misc.py` | #3, #8 — transporte inseguro e parsing do `.env` |
| `poc6_xml.py` | #6 — parser XML (negativo) |

`poc1_aia.py` sobe um servidor HTTP em `127.0.0.1:8899` (porta fixa, porque a URL está gravada
dentro do `.pfx`); `poc4_retry.py` usa porta efêmera. Saídas capturadas em
[`../RESULTADOS.md`](../RESULTADOS.md).
