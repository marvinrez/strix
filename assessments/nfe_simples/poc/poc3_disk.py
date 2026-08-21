"""PoC-3: material sensivel gravado em disco - chave privada em claro em /tmp e
saidas fiscais (PII + CNPJ + XML assinado) com permissoes de leitura para todos."""
import os, stat, json, pathlib, tempfile
from nfe.api_client import _extract_mutual_tls_files

cert, key = _extract_mutual_tls_files("workdir/certs/certificado-a1.pfx", "senha123")
print("[*] arquivos temporarios de mTLS:")
for f in (cert, key):
    print(f"    {f}  modo={stat.filemode(os.stat(f).st_mode)}")
head = open(key).read().splitlines()[0]
print("    primeira linha da chave:", head, "  <- PKCS8 SEM criptografia (NoEncryption)")
print("    dir do arquivo:", os.path.dirname(key), " modo do dir:", stat.filemode(os.stat(tempfile.gettempdir()).st_mode))
os.unlink(cert); os.unlink(key)

print("\n[*] saidas do CLI (mkdir/write_text sem modo explicito):")
d = pathlib.Path("demo_results/2026-08-21_355030821234567800019910000000000000001")
d.mkdir(parents=True, exist_ok=True)
(d/"resultado.json").write_text(json.dumps({"emit":{"headers":{"set-cookie":"..."}}}))
(d/"dps-assinada.xml").write_bytes(b"<DPS>...CNPJ, nome e endereco do tomador...</DPS>")
for p in (d.parent, d, d/"resultado.json", d/"dps-assinada.xml"):
    print(f"    {stat.filemode(os.stat(p).st_mode)}  {p}")
print("    umask atual:", oct(os.umask(0o022)))
