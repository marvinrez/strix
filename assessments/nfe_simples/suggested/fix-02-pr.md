## Problema

Quando `certificate.chain_path` não é informado, o emissor lê a extensão *Authority Information Access* do `.pfx` e baixa cada URL de `CA_ISSUERS`:

```python
# src/nfe/config.py:91-97
for url in urls:
    try:
        with urlopen(url, timeout=10) as resp:  # nosec B310 - trusted CA endpoints from cert
            downloaded = resp.read()
```

Duas coisas se combinam mal aqui.

A primeira: essa URL não vem do runtime, vem de dentro do arquivo `.pfx`. Um certificado é um arquivo que o operador trata como dado — recebe da AC, do contador, de um backup — e não como código. Mas o campo AIA é controlado por quem gerou o certificado, e o `# nosec B310` silencia exatamente o alerta que apontaria isso, sobre a premissa `trusted CA endpoints` que não se sustenta.

A segunda: o opener padrão do `urllib` entende `file://` e `ftp://`, além de http(s). Não há validação de esquema, de host, nem teto no `resp.read()`.

## Reprodução

Um `.pfx` de teste com AIA apontando para `file:///etc/passwd`:

```python
from nfe.config import _generate_chain_pem_from_pfx
from pathlib import Path

_generate_chain_pem_from_pfx(Path("cert-com-aia-file.pfx"), "senha")
```

Antes desta mudança o `urlopen` abre `file:///etc/passwd`. Com o AIA apontando para `http://127.0.0.1:8899/`, a requisição chega ao servidor interno — SSRF cega contra rede interna ou endpoint de metadata em nuvem, disparada por um certificado.

## A mudança

A busca passa a usar um `OpenerDirector` montado só com `HTTPHandler` e `HTTPSHandler`:

```python
opener = OpenerDirector()
for handler in (HTTPHandler(), HTTPSHandler(), HTTPDefaultErrorHandler(),
                HTTPErrorProcessor(), _SchemeCheckingRedirectHandler()):
    opener.add_handler(handler)
```

Sem `FileHandler` e sem `FTPHandler`, um esquema fora de http(s) falha por **ausência de handler** — não por depender de uma checagem `if` que alguém possa remover num refactor futuro. Sobre isso:

- o esquema é validado antes da chamada, então o caso comum falha rápido e o motivo fica explícito no código;
- redirecionamento para fora de http(s) não é seguido (`urllib` permite redirect para `ftp://` por padrão, o que reabriria o buraco);
- a resposta tem teto de 1 MiB — cadeias reais têm alguns KB.

Cadeias servidas por http(s), que é o caso real das ACs da ICP-Brasil, continuam funcionando sem mudança nenhuma. Verifiquei com um certificado DER servido por HTTP local: baixa e parseia igual.

## Testes

Cinco casos novos em `tests/test_config_aia.py`:

| Caso | Espera |
| --- | --- |
| `file:///tmp/segredo.txt` | lista vazia, nenhuma leitura |
| `ftp://127.0.0.1/cadeia.p7b` | lista vazia |
| 302 de `http://` para `file://` | não segue |
| resposta acima de 1 MiB | descartada |
| certificado DER por HTTP | parseado corretamente |

Suíte completa: 12 passando.

## Alternativa que considerei

Tornar a busca opt-in (`certificate.fetch_chain: false` por padrão, com `chain_path` como caminho documentado) seria mais conservador ainda — buscar cadeia na rede é conveniência, não requisito. Não fiz porque quebraria quem hoje depende do comportamento automático. Fica como sugestão, se você achar que vale.

Este é o segundo de alguns achados de uma revisão de segurança do repositório. O primeiro está em #<número do PR anterior>.
