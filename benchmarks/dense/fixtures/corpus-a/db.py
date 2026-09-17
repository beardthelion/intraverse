"""Generated sqlite store."""

import sqlite3

conn = sqlite3.connect("app.db", check_same_thread=False)
conn.execute("CREATE TABLE IF NOT EXISTS docs (id INTEGER, title TEXT, owner TEXT, body TEXT)")
if not conn.execute("SELECT COUNT(*) FROM docs").fetchone()[0]:
    conn.executemany(
        "INSERT INTO docs VALUES (?, ?, ?, ?)",
        [(1, "hello", "u1", "first doc"), (2, "notes", "u2", "second doc")],
    )
    conn.commit()
