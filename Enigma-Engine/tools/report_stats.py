import re

with open(r'C:\Users\pc\Desktop\Enigma IDE Local\Enigma-Engine\test_binaries\phase4_report.html') as f:
    html = f.read()

# Extract all section cards
cards = re.findall(r'ending-bad.*?<h3>([^<]+)</h3>', html, re.DOTALL)
print(f"Bad-ending functions ({len(cards)}):")
for c in cards:
    print(f"  {c.strip()}")

# Extract good-ending ones
cards_good = re.findall(r'<div class=[\'"]section-card[\'"]>\s*\n\s*<h3>([^<]+)</h3>', html)
print(f"\nGood-ending functions ({len(cards_good)}):")
for c in cards_good:
    print(f"  {c.strip()}")
