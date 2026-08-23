import csv
from collections import defaultdict

data = defaultdict(list)
with open("sweep_results.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        scenario = row["scenario"]
        scheduler = row["scheduler"]
        ratio = float(row["interception_ratio"])
        rate = float(row["intercept_rate"])
        data[(scenario, scheduler)].append((ratio, rate))

for (sc, sh), vals in data.items():
    avg_ratio = sum(v[0] for v in vals) / len(vals)
    avg_rate = sum(v[1] for v in vals) / len(vals)
    print(f"{sc} | {sh} | Ratio: {avg_ratio:.3f} | Rate: {avg_rate:.3f}")
