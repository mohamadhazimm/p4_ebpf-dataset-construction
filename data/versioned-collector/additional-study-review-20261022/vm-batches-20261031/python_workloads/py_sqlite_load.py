"""Benign database load: insert 50,000 rows into an SQLite file in batches and run aggregate queries."""
import json, random, sqlite3, sys
random.seed(3)
db = sqlite3.connect("inventory.db")
db.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, category TEXT, price REAL, qty INTEGER)")
for start in range(0, 50000, 5000):
    db.executemany("INSERT INTO items VALUES (?,?,?,?)",
                   [(i, "c%d" % (i % 40), random.uniform(1, 100), random.randint(0, 50)) for i in range(start, start + 5000)])
    db.commit()
db.execute("CREATE INDEX by_cat ON items(category)")
rows = db.execute("SELECT category, COUNT(*), SUM(price*qty) FROM items GROUP BY category").fetchall()
db.close()
print(json.dumps({"workload": "sqlite_load", "ok": len(rows) == 40, "groups": len(rows)}))
sys.exit(0 if len(rows) == 40 else 1)
