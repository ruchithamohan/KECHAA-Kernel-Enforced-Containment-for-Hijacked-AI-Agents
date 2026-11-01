"""Harmless local SQL workload; this standalone run is NOT KECHAA containment.

Creates only an in-memory database and prints a SELECT result. To contain a SQL
tool process, submit this script through a prepared Linux KECHAA run. KECHAA
restricts process effects; it does not authorize SQL statements or remote DB rows.
"""
import json
import sqlite3
from contextlib import closing

with closing(sqlite3.connect(':memory:')) as db:
    db.execute('CREATE TABLE tasks (id INTEGER PRIMARY KEY, title TEXT)')
    db.execute('INSERT INTO tasks (title) VALUES (?)', ('review policy',))
    print(json.dumps({'rows': db.execute('SELECT id, title FROM tasks').fetchall(),
                      'boundary': 'standalone local workload; no KECHAA containment'}))
