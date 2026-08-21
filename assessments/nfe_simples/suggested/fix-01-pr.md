## Problema

`_load_dotenv()` escreve em `os.environ` **toda** chave encontrada no `.env`, sem filtro:

```python
# src/nfe/config.py:33-34
if key and key not in os.environ:
    os.environ[key] = value
```

Esse `.env` é lido do diretório do `params.json` (`config.py:125`), que na prática costuma vir de fora: do contador, de um diretório compartilhado, de um runner de CI. A intenção documentada no README é apenas `CERT_PASSWORD`, mas o código aceita qualquer chave.

O problema é que três dessas chaves são lidas pelo `requests` **em tempo de requisição**, depois que o `NfseApiClient` já foi construído:

| Variável | Efeito |
| --- | --- |
| `HTTPS_PROXY` | todo o tráfego passa por um proxy escolhido por quem escreveu o `.env` |
| `REQUESTS_CA_BUNDLE` | substitui a âncora de confiança — `verify=True` passa a validar contra outra CA |
| `CURL_CA_BUNDLE` | idem |

Juntas, derrotam a verificação TLS do canal mTLS com a SEFIN. E `request.verify_tls: true` não protege: a injeção acontece **fora** do modelo Pydantic, então nenhuma validação do `params.json` a alcança.

## Reprodução

Um `.env` ao lado do `params.json`, com três linhas a mais do que o README pede:

```
CERT_PASSWORD=senha-real
HTTPS_PROXY=http://127.0.0.1:9999
REQUESTS_CA_BUNDLE=/tmp/ca-do-atacante.pem
```

```python
from nfe.config import load_params
import requests

load_params("params.json")
print(requests.utils.get_environ_proxies("https://sefin.nfse.gov.br/SefinNacional"))
print(requests.Session().merge_environment_settings(
    "https://sefin.nfse.gov.br/SefinNacional", {}, None, True, None)["verify"])
```

Antes desta mudança, em ambiente limpo:

```
{'https': 'http://127.0.0.1:9999'}
/tmp/ca-do-atacante.pem
```

Depois:

```
{}
True
```

## A mudança

Uma allowlist com as duas chaves que o `load_params` de fato consulta:

```python
_ALLOWED_ENV_KEYS = frozenset({"CERT_PASSWORD", "NFE_CERT_PASSWORD"})
```

O comportamento documentado fica idêntico — quem só põe `CERT_PASSWORD` no `.env` não percebe diferença. O resto do arquivo passa a ser ignorado.

Três testes de regressão: chaves fora da allowlist são ignoradas, ambas as chaves de senha funcionam, e o ambiente existente continua tendo precedência sobre o arquivo. Suíte completa: 10 passando.

## O que deixei de fora, de propósito

- **`session.trust_env = False`** no `NfseApiClient` neutralizaria essas variáveis vindas de qualquer origem, não só do `.env`. É mais robusto, mas quebraria quem depende de proxy corporativo legítimo — merece decisão sua, em PR separado.
- **O parsing do `.env`** (`value.strip().strip('"').strip("'")`) remove aspas repetidas das duas pontas: uma senha `"Ab#123""` é lida como `Ab#123`. É um bug real, mas independente deste — não misturei.

Achei isto numa revisão de segurança do repositório. Há outros achados, com PoC, que posso abrir como issues separadas se for útil.
