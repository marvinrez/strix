## Problema

Dois pontos gravam dado sensível com permissão mais aberta do que precisam.

### Os arquivos de mTLS

```python
# src/nfe/api_client.py:36-49
key_pem = private_key.private_bytes(
    ..., encryption_algorithm=serialization.NoEncryption(),
)
...
key_file = tempfile.NamedTemporaryFile(prefix="nfe-key-", suffix=".pem", delete=False)
```

A chave privada do A1 sai do `.pfx` em PKCS#8 **sem criptografia** — o `requests` precisa dela assim, não há como evitar. O `NamedTemporaryFile` já nasce `0600`, o que está certo, mas os arquivos ficam soltos em `/tmp`, que é `drwxrwxrwt`, e só somem no `__exit__` (`api_client.py:106-110`).

Se o processo cair, for interrompido, ou se o `NfseApiClient` for usado sem o `with`, a chave privada do certificado A1 fica em disco por tempo indeterminado.

### As saídas

`cli.py` cria `results/` e grava com o modo do umask:

```
drwxr-xr-x  results/
-rw-r--r--  results/<data>_<id>/dps-assinada.xml     ← CNPJ, valores, dados do tomador
-rw-r--r--  results/<data>_<id>/resultado.json
```

Qualquer usuário da máquina lê. Numa máquina de contabilidade com mais de um login, ou num runner compartilhado, isso importa.

## A mudança

| | Antes | Depois |
| --- | --- | --- |
| diretório dos arquivos mTLS | `/tmp` (`drwxrwxrwt`) | `mkdtemp` próprio (`drwx------`) |
| limpeza | só no `__exit__` | `__exit__` + `atexit` + falha na extração |
| `results/` e subpastas | `drwxr-xr-x` | `drwx------` |
| `dps-assinada.xml`, `resultado.json` | `-rw-r--r--` | `-rw-------` |

Nenhuma mudança de interface: `_extract_mutual_tls_files` é privada e passa a devolver também o diretório, para que o cliente saiba o que remover.

## Um detalhe que só apareceu escrevendo o teste

A primeira versão do `_mkdir_private` era:

```python
path.mkdir(mode=PRIVATE_DIR_MODE, parents=True, exist_ok=True)
path.chmod(PRIVATE_DIR_MODE)
```

O `mkdir(parents=True)` aplica o `mode` **só ao último nível**; os intermediários saem com o padrão do umask. O teste que checa o modo de `results/` pegou isso. A versão final cria um nível por vez, e só os que faltam, para não alterar o modo de diretórios que já existiam por outro motivo.

## O que deixei de fora

`_normalize_response` serializa `dict(resp.headers)` inteiro no `resultado.json` (`api_client.py:73`). Filtrar para uma allowlist seria coerente com este PR, mas muda o formato de um arquivo que talvez alguém já leia, e o risco concreto é baixo — os headers da SEFIN não devem carregar segredo. Fica como decisão sua.

## Testes

Cinco casos em `tests/test_private_files.py`: modos dos arquivos de mTLS, remoção do diretório ao sair do contexto, senha errada não deixando diretório para trás, modos das saídas do CLI, e um `results/` preexistente em `0755` sendo corrigido. Os que checam modo POSIX são pulados no Windows.

Suíte completa: 12 passando.

Quinto de alguns achados de uma revisão de segurança do repositório.
