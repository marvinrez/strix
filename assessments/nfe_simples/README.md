# Revisão de segurança — `danielcarletti/nfe_simples`

Revisão white-box do emissor de NFS-e (Sistema Nacional / API Contribuintes), commit `a20bada`,
seguindo a metodologia da skill [`find-security-vulnerabilities-in-code`](../../skills/find-security-vulnerabilities-in-code/SKILL.md)
do Strix: ler o código para montar o modelo de fluxo de dados e fronteiras de confiança, e então
**provar** cada achado com um PoC executável em vez de reportar alerta de padrão.

Escopo: `src/nfe/` (627 linhas, 6 módulos), `params.example.json`, `.gitignore`, `pyproject.toml`.
Sem endpoint vivo — a API SEFIN é de terceiros e está fora de escopo de teste.

> **Como isto foi executado.** O sandbox desta sessão não tem Docker, então o agente autônomo do
> Strix (`strix -n -t ./`) não pôde rodar aqui. A revisão foi feita manualmente sobre a metodologia
> da skill, e **todos os achados de severidade Alta e Média foram reproduzidos com PoC executado**
> (`poc/`, saídas em [`RESULTADOS.md`](RESULTADOS.md)). Para a passada autônoma completa, veja
> [Rodando o Strix de verdade](#rodando-o-strix-de-verdade).

---

## Modelo de ameaça

O emissor é uma ferramenta de linha de comando operada pelo contribuinte, mas manipula os dois
ativos mais sensíveis da emissão fiscal:

| Ativo | Onde vive |
| --- | --- |
| Chave privada do certificado A1 ICP-Brasil | `.pfx`, senha em `.env` ou `params.json` |
| Canal mTLS com a SEFIN Nacional | `api_client.NfseApiClient` |
| DPS assinada (CNPJ, valores, PII do tomador) | `results/<data>_<id>/` |

As entradas que cruzam fronteira de confiança são: **`params.json`**, o **`.env` ao lado dele**, o
**arquivo `.pfx`** e as **respostas HTTP da API**. Nenhuma delas é tratada como não confiável hoje.
Os cenários realistas de comprometimento são um `params.json` recebido do contador/terceiro, um
diretório de trabalho compartilhado, um runner de CI, ou um `.pfx` obtido de fora.

---

## Achados

Ordenados por impacto provado, não por severidade de scanner.

| # | Achado | Severidade | Arquivo | PoC |
| --- | --- | --- | --- | --- |
| 1 | `.env` injeta qualquer variável de ambiente → MITM do canal mTLS | **Alta** | `config.py:22-34` | `poc2_dotenv.py` ✅ |
| 2 | SSRF e leitura de arquivo local no download automático da cadeia AIA | **Alta** | `config.py:91-97` | `poc1_aia.py` ✅ |
| 3 | TLS desligável e URL base arbitrária, sem guarda-corpo em produção | **Alta** | `models.py:25-26`, `api_client.py:81-88` | `poc5_misc.py` ✅ |
| 4 | Retry de `POST /nfse` não idempotente → nota fiscal duplicada | **Média** | `api_client.py:112-124` | `poc4_retry.py` ✅ |
| 5 | Chave privada em claro no disco e saídas fiscais legíveis por todos | **Média** | `api_client.py:26-56`, `cli.py:39-46,68,82` | `poc3_disk.py` ✅ |
| 6 | Parser XML padrão em API pública de assinatura | Baixa | `xml_signer.py:34` | `poc6_xml.py` ⚠️ não explorável hoje |
| 7 | Falha silenciosa na montagem da cadeia de certificados | Baixa | `config.py:47,59,96` | bandit B110/B112 |
| 8 | Parsing de `.env` corrompe senhas com aspas | Baixa | `config.py:32` | `poc5_misc.py` ✅ |
| 9 | Sem CI, sem SCA, sem secret scanning, sem pin de dependências | Baixa | — | — |
| 10 | `certificate.password` aceito em texto claro no `params.json` | Baixa | `models.py:15`, `config.py:127-132` | — |

---

### 1. `.env` injeta qualquer variável de ambiente → MITM do canal mTLS · **Alta** · CWE-15

`_load_dotenv()` lê o `.env` **do diretório do `params.json`** e escreve **toda** chave encontrada
em `os.environ`, sem allowlist:

```python
# src/nfe/config.py:33-34
if key and key not in os.environ:
    os.environ[key] = value
```

A intenção documentada é apenas `CERT_PASSWORD`. Na prática, quem controla o diretório do
`params.json` controla o ambiente do processo — inclusive as variáveis que o `requests` lê **em
tempo de requisição**, depois que o cliente já foi construído:

- `HTTPS_PROXY` → todo o tráfego passa por um proxy escolhido pelo atacante;
- `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` → substitui a âncora de confiança, e `verify=True`
  passa a validar contra a CA do atacante.

Combinadas, derrotam completamente a verificação TLS do canal com a SEFIN. Nem `verify_tls: true`
nem a checagem do `params.json` protegem, porque a injeção acontece **fora** do modelo Pydantic.

**Provado** (`poc2_dotenv.py`, ambiente limpo): um `.env` com três linhas a mais faz
`requests.utils.get_environ_proxies()` retornar `{'https': 'http://127.0.0.1:9999'}` e
`merge_environment_settings(...)['verify']` virar `/tmp/ca-do-atacante.pem`.

**Correção.** Importar somente as chaves esperadas, e não confiar em diretório de terceiro:

```python
_ALLOWED_ENV_KEYS = frozenset({"CERT_PASSWORD", "NFE_CERT_PASSWORD"})

for line in dotenv_path.read_text(encoding="utf-8").splitlines():
    ...
    if key in _ALLOWED_ENV_KEYS and key not in os.environ:
        os.environ[key] = value
```

Vale ainda: só ler o `.env` se ele pertencer ao usuário atual e não for gravável por outros
(`os.stat`), e neutralizar proxy/CA explicitamente no cliente (`session.trust_env = False`,
`session.verify = certifi.where()`), já que o canal é mTLS com um host fixo e conhecido.

---

### 2. SSRF e leitura de arquivo local no download da cadeia AIA · **Alta** · CWE-918

Quando `chain_path` não é informado, o código lê a extensão *Authority Information Access* do
certificado e baixa cada URL de `CA_ISSUERS`:

```python
# src/nfe/config.py:91-97
for url in urls:
    try:
        with urlopen(url, timeout=10) as resp:  # nosec B310 - trusted CA endpoints from cert
            downloaded = resp.read()
```

O comentário `# nosec B310` suprime exatamente o alerta que apontaria o problema — e a premissa
("trusted CA endpoints") não se sustenta: a URL vem do **arquivo `.pfx`**, que é entrada do
usuário, não do runtime. Não há allowlist de esquema, allowlist de host, nem limite de tamanho no
`resp.read()`.

**Provado** (`poc1_aia.py`): um `.pfx` de teste com AIA apontando para `file:///etc/passwd` faz o
`urlopen` abrir o arquivo local; com AIA apontando para `http://127.0.0.1:8899/`, a requisição
chega ao servidor interno. `urlopen` aceita `file://`, `http://` e `ftp://`.

Impacto: leitura de arquivo local e SSRF cega contra a rede interna / metadata de nuvem, disparadas
por um certificado — o tipo de arquivo que o operador trata como dado, não como código.

**Correção.**

```python
from urllib.parse import urlparse

MAX_CHAIN_BYTES = 1 << 20

for url in urls:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        continue
    try:
        with urlopen(url, timeout=10) as resp:
            downloaded = resp.read(MAX_CHAIN_BYTES + 1)
        if len(downloaded) > MAX_CHAIN_BYTES:
            continue
```

Melhor ainda: tornar o download opt-in (`certificate.fetch_chain: false` por padrão) e documentar
`chain_path` como o caminho recomendado. Buscar cadeia na rede é conveniência, não requisito.

---

### 3. TLS desligável e URL base arbitrária, sem guarda-corpo em produção · **Alta** · CWE-295, CWE-319

```python
# src/nfe/models.py:25-26
verify_tls: bool = True
api_base_url_override: str | None = None
```

`verify_tls: false` desativa a validação do certificado do servidor. `api_base_url_override` aceita
qualquer string, inclusive `http://`, sem validação de esquema ou host. As duas são aceitas em
`environment: "producao"` sem aviso, e o `api_base_url_override` tem precedência sobre a URL oficial
(`api_client.py:81-85`).

**Provado** (`poc5_misc.py`): `environment=producao`, `verify_tls=False`,
`base_url=http://api-do-atacante.example/SefinNacional`, tudo aceito em silêncio. Em `poc4_retry.py`
a DPS assinada foi transmitida por HTTP em texto claro para um servidor local.

O agravante é o README, que sugere o override como remédio para o erro `495 SSL Certificate Error`
— justamente o erro que leva um operador apressado a desligar TLS.

**Correção.** Validar no `RequestConfig` e falhar em produção:

```python
@model_validator(mode="after")
def enforce_secure_transport(self) -> "RequestConfig":
    if self.api_base_url_override:
        parsed = urlparse(self.api_base_url_override)
        if parsed.scheme != "https":
            raise ValueError("request.api_base_url_override deve usar https://")
    return self
```

E, no `NfseParams`, recusar `verify_tls: false` quando `environment == "producao"`, exigindo um opt-in
explícito e ruidoso (`NFE_ALLOW_INSECURE_TLS=1`) nos demais casos. Trocar `verify_tls: bool` por
`verify_tls: bool | str` também permite apontar um bundle de CA — a saída correta para o erro 495,
em vez de desligar a verificação.

---

### 4. Retry de `POST /nfse` não idempotente → nota fiscal duplicada · **Média**

```python
# src/nfe/api_client.py:117-122
for _ in range(attempts):
    try:
        resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
        return _normalize_response(resp)
    except requests.RequestException as exc:
        last_exc = exc
```

O laço retenta **qualquer** método, inclusive `POST /nfse`, em **qualquer** `RequestException` —
inclusive `ReadTimeout` e conexão encerrada, casos em que a requisição chegou ao servidor e a
resposta é que se perdeu. Não há backoff nem chave de idempotência.

**Provado** (`poc4_retry.py`): um servidor que processa o POST e derruba a conexão antes de
responder recebe **duas** emissões da mesma nota. Com `retries: 5` (o máximo permitido), seis.

Numa API fiscal isso não é um retry perdido: é uma NFS-e a mais, com número de DPS já consumido e
cancelamento manual pela frente.

**Correção.** Retentar somente métodos idempotentes; para o POST, em caso de timeout, consultar
`GET /dps/{id}` antes de reenviar — o identificador determinístico de `build_dps_identifier()` já
existe exatamente para isso:

```python
IDEMPOTENT = {"GET", "HEAD", "OPTIONS"}
attempts = self.retries + 1 if method.upper() in IDEMPOTENT else 1
```

Adicionar backoff exponencial nos métodos que puderem ser retentados.

---

### 5. Chave privada em claro no disco e saídas fiscais legíveis por todos · **Média** · CWE-522, CWE-732

```python
# src/nfe/api_client.py:36-49
key_pem = private_key.private_bytes(
    ..., encryption_algorithm=serialization.NoEncryption(),
)
...
key_file = tempfile.NamedTemporaryFile(prefix="nfe-key-", suffix=".pem", delete=False)
```

A chave privada do A1 é escrita **descriptografada** em `/tmp`. Os arquivos temporários nascem
`0600` (correto), mas ficam num diretório world-writable e só são removidos em `__exit__`
(`api_client.py:106-110`) — se o processo for morto, cair ou se `NfseApiClient` for usado sem
`with`, a chave persiste em disco indefinidamente.

Do lado das saídas, `cli.py` cria `results/` e grava com o modo padrão:

```
drwxr-xr-x  results/
-rw-r--r--  results/<data>_<id>/dps-assinada.xml     ← CNPJ, valores, PII do tomador
-rw-r--r--  results/<data>_<id>/resultado.json       ← inclui dict(resp.headers) da API
```

**Provado** (`poc3_disk.py`).

**Correção.**

- `Path("results").mkdir(mode=0o700, ...)` e `os.chmod(path, 0o600)` após cada escrita (ou
  `os.umask(0o077)` no início do `run()`);
- criar os arquivos mTLS num diretório dedicado 0700 (`tempfile.mkdtemp`), envolver em
  `try/finally` e registrar `atexit`/`shutil.rmtree` para que o `unlink` aconteça mesmo em falha;
- filtrar `_normalize_response` para uma allowlist de headers, em vez de serializar `dict(resp.headers)`
  inteiro num arquivo que fica em disco.

---

### 6. Parser XML padrão em API pública de assinatura · Baixa · CWE-611 (defesa em profundidade)

`sign_dps_xml(xml_bytes, ...)` chama `etree.fromstring(xml_bytes)` (`xml_signer.py:34`) sem parser
endurecido. Hoje o único chamador passa a saída do próprio `dps_builder`, e no lxml 6.1.2 /
libxml2 2.14.6 desta sessão **entidades externas já vêm bloqueadas por padrão** — confirmado em
`poc6_xml.py`, que levanta `XMLSyntaxError: Entity 'xxe' not defined`. **Não é explorável hoje.**

O que ainda vale: entidades internas expandem (10 KB a partir de ~300 bytes de entrada), o
comportamento depende da versão do libxml2 e a função é pública, aceitando bytes arbitrários.
Custo da blindagem é uma linha:

```python
_PARSER = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
doc = etree.fromstring(xml_bytes, parser=_PARSER)
```

---

### 7-10. Endurecimento

**7 — Falha silenciosa na cadeia** (`config.py:47,59,96`). Três `except Exception: pass/continue`
(bandit B110/B112) engolem qualquer erro ao montar a cadeia. O resultado é o `495 SSL Certificate
Error` opaco em produção, sem nenhuma pista de por que a cadeia não foi montada. Registrar em log
o motivo em vez de descartar.

**8 — Parsing frágil do `.env`** (`config.py:32`). `value.strip().strip('"').strip("'")` remove
aspas **repetidas** de ambas as pontas e sempre corta espaços. Provado em `poc5_misc.py`:
`CERT_PASSWORD="Ab#123""` é lido como `Ab#123`, não `Ab#123"`. Uma senha de certificado com aspas
ou espaços significativos falha de forma inexplicável. Usar `python-dotenv` ou remover no máximo
um par de aspas correspondentes.

**9 — Sem CI e sem cadeia de suprimentos.** O repositório não tem `.github/`: nenhum teste roda
automaticamente, nenhum SCA, nenhum secret scanning. As dependências usam apenas piso
(`cryptography>=42.0.0`) sem lock. `pip-audit` está limpo hoje contra as versões declaradas, mas
nada trava uma regressão. Workflow sugerido em [`suggested/security.yml`](suggested/security.yml).

**10 — Senha em texto claro no `params.json`.** `CertificateConfig.password` (`models.py:15`) aceita
a senha do A1 no JSON, e `load_params` a prefere sobre a variável de ambiente
(`config.py:127-132`). O `.gitignore` cobre `params.json`, o que reduz muito o risco, mas o campo
convida a colar a senha num arquivo que acaba em backup, anexo de e-mail ou `params.example.json`
por descuido. Considerar remover o campo e aceitar somente `CERT_PASSWORD`.

---

## O que já está certo

Vale registrar, porque não é o padrão em emissores fiscais:

- **`.gitignore` cobre o que importa** — `params.json`, `.env`, `/certs`, `/results` estão todos
  ignorados (verificado com `git check-ignore`). Nenhum segredo no histórico.
- **mTLS com verificação de TLS ligada por padrão**, e ambientes `producao` / `producao_restrita`
  separados desde o modelo.
- **XML construído com a API de elementos do lxml**, não por concatenação de string — não há
  injeção de XML pelos campos do `params.json`.
- **Validação de entrada com Pydantic** em toda a superfície de configuração, com validadores de
  CPF/CNPJ e código IBGE.
- **Arquivos temporários de mTLS nascem `0600`** e são removidos no caminho feliz.
- `pip-audit` sem CVEs conhecidas nas dependências declaradas.

---

## Reproduzindo

```bash
git clone https://github.com/danielcarletti/nfe_simples && cd nfe_simples
pip install -e ".[dev]"
cp -r /caminho/para/assessments/nfe_simples/poc . && cd poc

python setup_fixtures.py   # gera os .pfx de teste, o workdir/params.json e o .env do PoC-2

python poc1_aia.py         # SSRF / file:// na cadeia AIA
python poc3_disk.py        # chave em claro + permissões das saídas
python poc4_retry.py       # emissão duplicada
python poc5_misc.py        # parsing do .env, TLS desligado, http:// aceito
python poc6_xml.py         # parser XML (negativo — não explorável hoje)

# o PoC-2 precisa de ambiente sem proxy herdado:
env -i PATH="$PATH" PYTHONPATH="$PWD/../src" python poc2_dotenv.py
```

Detalhes em [`poc/README.md`](poc/README.md).

Todos os certificados são auto-assinados e gerados na hora. Nenhum PoC toca a API da SEFIN.
Saídas capturadas em [`RESULTADOS.md`](RESULTADOS.md).

## Rodando o Strix de verdade

Esta revisão seguiu a metodologia da skill, mas sem o agente autônomo (o sandbox não tem Docker).
Com Docker e uma chave de LLM:

```bash
curl -sSL https://strix.ai/install | bash
export STRIX_LLM="anthropic/claude-sonnet-5"
export LLM_API_KEY="..."

strix -n -t https://github.com/danielcarletti/nfe_simples --max-budget 15 \
  --instruction "CLI de emissão fiscal. Entradas não confiáveis: params.json, o .env ao lado dele, o arquivo .pfx e as respostas da API SEFIN. Ativos: chave privada do certificado A1 e o canal mTLS. Priorize config.py (carga do .env e download da cadeia AIA) e api_client.py (construção da URL base, verificação de TLS, laço de retry)."
```

Resultados em `strix_runs/<run>/penetration_test_report.md` e `vulnerabilities/*.md`.

Vale contrastar com o que o scanner de padrão viu: `bandit -r src` reportou **3 achados Low**, todos
`try/except/pass` — e suprimiu o `B310` do achado #2 por causa do `# nosec` no próprio código. Nenhum
dos achados Alta aparece numa varredura de padrão, porque todos dependem de raciocínio sobre fluxo
de dados através de fronteira de confiança.

## Sugestão de contribuição

Ordem proposta para o upstream, do maior impacto ao menor atrito:

1. Allowlist de chaves no `_load_dotenv` (#1) — 3 linhas, sem quebra de compatibilidade.
2. Allowlist de esquema e limite de tamanho no fetch AIA (#2) — 6 linhas.
3. Validação de `https://` no override e recusa de `verify_tls: false` em produção (#3).
4. Retry só em métodos idempotentes (#4) — evita nota duplicada.
5. `umask`/`chmod` nas saídas e limpeza garantida dos temporários (#5).
6. Workflow de CI com testes + `pip-audit` + Strix diff-scoped (#9).

Itens 1-4 cabem num PR pequeno cada, com teste de regressão. O #9 é o que impede a regressão dos
demais.
