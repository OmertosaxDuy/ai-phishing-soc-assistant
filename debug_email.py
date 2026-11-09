from pathlib import Path
from core.email_parser import parse_email

path = Path("data/samples/phishing_01.eml")
raw = path.read_bytes()

print("FIRST 150 BYTES:")
print(repr(raw[:150]))

result = parse_email(raw)

print("\nSUBJECT:", result["subject"])
print("FROM:", result["from"])
print("TO:", result["to"])
print("HTML LENGTH:", len(result["body_html"]))
print("MISMATCHES:", result["iocs"]["link_mismatches"])