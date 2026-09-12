from __future__ import annotations
import sqlite3
from pathlib import Path
from contextlib import contextmanager
from database.schema import DDL, SCHEMA_VERSION

class DatabaseManager:
    def __init__(self, path: str | Path):
        self.path=Path(path); self.path.parent.mkdir(parents=True,exist_ok=True); self.initialize()
    @contextmanager
    def connection(self):
        con=sqlite3.connect(self.path, timeout=15, isolation_level="IMMEDIATE")
        con.row_factory=sqlite3.Row
        try:
            con.execute("PRAGMA foreign_keys=ON"); yield con; con.commit()
        except Exception: con.rollback(); raise
        finally: con.close()
    def initialize(self):
        with self.connection() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(DDL)
            if c.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]==0: c.execute("INSERT INTO schema_version VALUES (?)",(SCHEMA_VERSION,))
