import csv
from collections import defaultdict

data = defaultdict(lambda: {'count': 0, 'bins': set(), 'cats': set()})

with open(r'C:\Users\pc\Desktop\audit_merged.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        h = row.get('hash', '')
        cat = row.get('category', '')
        binary = row.get('binary', '')
        if h and cat != 'named':
            data[h]['count'] += 1
            data[h]['bins'].add(binary)
            data[h]['cats'].add(cat)

cross = [(h, v) for h, v in data.items() if len(v['bins']) >= 2]
cross.sort(key=lambda x: (-x[1]['count'], -len(x[1]['bins'])))

print(f'Total unique hashes: {len(data)}')
print(f'Cross-binary candidates: {len(cross)}')
print()
print(f'{"Hash":<20} {"Count":>6} {"Bins":>5}  {"Category":<16} Binaries')
print('-' * 90)
for h, v in cross[:40]:
    bins = ', '.join(sorted(v['bins']))
    cats = ', '.join(sorted(v['cats']))
    print(f'{h:<20} {v["count"]:>6} {len(v["bins"]):>5}  {cats:<16} {bins}')
