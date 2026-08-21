## Problema

Duas opções de `request` são aceitas em `producao` sem nenhum alerta:

```python
# src/nfe/models.py:25-26
verify_tls: bool = True
api_base_url_override: str | None = None
```

`verify_tls: false` desativa a validação do certificado do servidor. `api_base_url_override` aceita qualquer string — inclusive `http://` — e tem precedência sobre a URL oficial da SEFIN (`api_client.py:81-85`).

Com as duas, a DPS assinada, que carrega CNPJ, valores e dados do tomador, é transmitida em texto claro para um host arbitrário. Sem aviso.

O agravante está no próprio README:

> Observacao: os endpoints oficiais podem evoluir. Se necessário, use `request.api_base_url_override`.

E, mais acima, o `495 SSL Certificate Error`. Quem esbarra nesse erro tem duas alavancas à mão, ambas sem trava, e nenhuma delas é a correta.

## Reprodução

```python
from nfe.models import NfseParams
import json

p = json.load(open("params.example.json"))
p["environment"] = "producao"
p["request"]["verify_tls"] = False
p["request"]["api_base_url_override"] = "http://qualquer-host.example/SefinNacional"

NfseParams.model_validate(p)   # antes: aceito em silêncio
```

## A mudança

| Antes | Depois |
| --- | --- |
| `api_base_url_override: "http://..."` | recusado — exige `https://` e host |
| `verify_tls: false` em `producao` | recusado, com a alternativa na mensagem |
| `verify_tls: false` em `producao_restrita` | aceito, com aviso |
| — | `verify_tls: "./ca-bundle.pem"` aceito em qualquer ambiente |

A última linha entra **de propósito**. Sem ela, esta mudança só retiraria a saída de emergência de quem esbarra no 495, sem oferecer o caminho correto — e a pessoa acabaria fazendo um fork ou editando o `models.py` na mão, que é pior. O `requests` já aceita um caminho em `verify`, então o `api_client` não muda uma linha; o caminho é resolvido em relação ao `params.json`, exatamente como o `certificate.chain_path` já é.

A mensagem de erro aponta a saída, em vez de só bloquear:

```
request.verify_tls: false nao e aceito em producao. Se o erro for
495 SSL Certificate Error, aponte request.verify_tls para o arquivo
do bundle de CA em vez de desativar a verificacao
```

## Compatibilidade

`params.example.json` continua válido sem alteração nenhuma. Quem usa `verify_tls: true` e `api_base_url_override: null` — o caso normal — não percebe diferença.

Quebra de propósito apenas para dois casos, ambos inseguros: `verify_tls: false` em produção e override `http://`. Se você preferir que produção também aceite `verify_tls: false` mediante opt-in explícito, dá para trocar o erro por uma checagem de variável de ambiente (`NFE_ALLOW_INSECURE_TLS=1`) — me diga e eu ajusto.

## Testes

Nove casos em `tests/test_secure_transport.py`: `http://` recusado, URL sem host, `https://` aceito, `verify_tls: false` recusado em produção e avisado fora dela, bundle aceito em produção, caminho relativo resolvido, bundle inexistente reportado, e o caminho chegando até o `NfseApiClient`.

Suíte completa: 16 passando.

O README ganhou duas linhas na seção do erro 495, documentando as opções.

Terceiro de alguns achados de uma revisão de segurança do repositório.

---

Revisao feita com [Strix](https://github.com/usestrix/strix), ferramenta open source de pentest por IA, com apoio do Claude. Cada achado tem prova de conceito executavel e teste de regressao. Relatorio completo, com os PoCs: https://github.com/marvinrez/strix/tree/claude/nfe-simples-security-cq5llr/assessments/nfe_simples
