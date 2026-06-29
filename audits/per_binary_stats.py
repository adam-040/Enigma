import csv
from collections import defaultdict

bins = defaultdict(lambda: {'total': 0, 'named': 0, 'cats': defaultdict(int), 'fail': defaultdict(int)})

with open(r'C:\Users\pc\Desktop\audit_merged.csv', 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        b = row['binary']
        bins[b]['total'] += 1
        cat = row['category']
        bins[b]['cats'][cat] += 1
        if cat == 'named':
            bins[b]['named'] += 1
        fail = row.get('failure', '')
        if fail:
            bins[b]['fail'][fail] += 1

for b in sorted(bins.keys()):
    d = bins[b]
    pct = 100.0 * d['named'] / d['total'] if d['total'] > 0 else 0
    print(f'{b}: total={d["total"]} named={d["named"]} ({pct:.1f}%)')
    for cat in sorted(d['cats'].keys()):
        c = d['cats'][cat]
        if cat != 'named':
            cpct = 100.0 * c / d['total']
            print(f'  {cat:<20} {c:>6}  ({cpct:.1f}%)')
    print('  Failure breakdown:')
    for fail in sorted(d['fail'].keys()):
        c = d['fail'][fail]
        cpct = 100.0 * c / d['total']
        print(f'    {fail:<24} {c:>6}  ({cpct:.1f}%)')
    print()
