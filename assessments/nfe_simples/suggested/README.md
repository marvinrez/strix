# Correções propostas para `danielcarletti/nfe_simples`

Um patch por achado do [relatório](../README.md). Todos partem do `main` (`a20bada`) e são
independentes: podem ser abertos como PRs em paralelo e mesclados em qualquer ordem.

| Achado | Patch | Corpo do PR | Branch sugerido |
| --- | --- | --- | --- |
| #1 — injeção de env via `.env` | `fix-01-dotenv-allowlist.patch` | `fix-01-pr.md` | `fix/dotenv-allowlist` |
| #2 — SSRF / `file://` na cadeia AIA | `fix-02-aia-allowlist.patch` | `fix-02-pr.md` | `fix/aia-scheme-allowlist` |
| #3 — transporte inseguro sem trava | `fix-03-secure-transport.patch` | `fix-03-pr.md` | `fix/secure-transport-guardrails` |
| #4 — retry de POST duplica nota | `fix-04-retry-policy.patch` | `fix-04-pr.md` | `fix/no-retry-on-post` |
| #5 — permissões em disco | `fix-05-private-files.patch` | `fix-05-pr.md` | `fix/private-files-on-disk` |

Falta ainda o #9 (CI), cujo workflow está em [`security.yml`](security.yml).

## Aplicando

```bash
git clone https://github.com/<seu-fork>/nfe_simples && cd nfe_simples
git checkout -b fix/dotenv-allowlist
git am /caminho/para/fix-01-dotenv-allowlist.patch
PYTHONPATH="$PWD/src" python -m pytest -q
```

O `PYTHONPATH` explícito importa: sem ele o `pytest` pode importar um `nfe` instalado em modo
editável em vez do `src/` do clone, e a suíte passa testando o código errado.

## Verificação

Cada patch foi aplicado a um clone virgem e a suíte rodada com o `PYTHONPATH` do próprio clone:

| | Testes |
| --- | --- |
| baseline, sem patch | 7 |
| #1 | 10 |
| #2 | 12 |
| #3 | 16 |
| #4 | 11 |
| #5 | 12 |
| os cinco empilhados | 33 |

Para empilhar todos, use `git am -3`: os patches #4 e #5 acrescentam imports diferentes ao mesmo
bloco do `api_client.py`, e a aplicação sequencial estrita esbarra nisso. Cada um aplica limpo
sobre o `main` isoladamente, que é como serão mesclados.

Os PoCs correspondentes em [`../poc/`](../poc/) deixam de funcionar com os patches aplicados —
essa é a verificação que importa, mais do que a contagem de testes.
