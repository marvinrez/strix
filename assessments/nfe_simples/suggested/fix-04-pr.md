## Problema

```python
# src/nfe/api_client.py:117-122
for _ in range(attempts):
    try:
        resp = self.session.request(method, url, timeout=self.timeout, **kwargs)
        return _normalize_response(resp)
    except requests.RequestException as exc:
        last_exc = exc
```

O laço repete **qualquer** método diante de **qualquer** `RequestException`. O detalhe que importa: essa exceção não distingue dois casos muito diferentes.

| Caso | O que aconteceu | Repetir é |
| --- | --- | --- |
| `ConnectionError` no handshake | não chegou ao servidor | seguro |
| `ReadTimeout`, conexão encerrada | chegou, foi processada, a resposta se perdeu | **emite a nota de novo** |

No segundo caso o `POST /nfse` reenvia a mesma DPS. Com o padrão `retries: 1` são duas emissões; com o máximo permitido pelo modelo, seis.

Numa API fiscal isso não é uma requisição perdida. É uma NFS-e a mais, com número de DPS já consumido e cancelamento manual pela frente.

## Reprodução

Um servidor que processa o POST e derruba a conexão antes de responder — exatamente o que uma queda de rede na volta produz:

```python
def do_POST(self):
    self.rfile.read(int(self.headers.get("content-length", 0)))
    recebidas.append(self.path)      # servidor já emitiu a nota
    self.close_connection = True     # resposta se perde
```

Antes: `POST /nfse recebidos pelo servidor: 2`. Depois: `1`, e o erro é reportado ao operador em vez de mascarado por uma segunda emissão.

## A mudança

```python
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
...
attempts = self.retries + 1 if method.upper() in IDEMPOTENT_METHODS else 1
```

`GET`, `HEAD` e `OPTIONS` continuam sendo repetidos até `request.retries`, agora com backoff exponencial em vez de reenvio imediato — o retry anterior disparava as tentativas em rajada, o que não ajuda numa indisponibilidade momentânea.

`request.retries` continua com o mesmo default e a mesma semântica para os métodos que ainda repetem.

## O que considerei e não fiz

O tratamento realmente completo seria: no timeout do POST, consultar `GET /dps/{id}` antes de decidir — o identificador determinístico de `build_dps_identifier()` existe exatamente para isso. Não implementei porque depende de saber o que a SEFIN devolve em `/dps/{id}` logo após uma emissão que pode ou não ter sido persistida, e eu não tenho como verificar isso contra a API real. Você tem.

Se quiser, o esqueleto é:

```python
def emit_nfse(self, signed_dps_xml: bytes, dps_id: str) -> dict:
    try:
        return self._request("POST", "/nfse", json=payload, headers=headers)
    except ApiClientError:
        ja_existe = self.head_by_dps_id(dps_id)
        if ja_existe["status_code"] == 200:
            return ja_existe          # a nota entrou; não reenviar
        raise
```

Isso muda a assinatura de `emit_nfse` e toca o `cli.py`, então fica melhor como PR separado, seu, com a semântica real da API em mãos.

## Testes

Quatro casos em `tests/test_retry_policy.py`: POST não repetido quando a resposta se perde, `GET` e `HEAD` repetidos até o limite, e POST bem-sucedido inalterado. Suíte completa: 11 passando.

Quarto de alguns achados de uma revisão de segurança do repositório.
