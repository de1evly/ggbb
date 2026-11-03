import sqlite3
import time


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS choices (
              network TEXT, service TEXT, route TEXT, changed REAL, expires REAL,
              failures INTEGER DEFAULT 0, last_used REAL, evidence TEXT, verified REAL,
              PRIMARY KEY(network, service));
            CREATE TABLE IF NOT EXISTS attempts (
              id INTEGER PRIMARY KEY, at REAL, network TEXT, service TEXT,
              route TEXT, outcome TEXT, latency_ms INTEGER, status INTEGER);
        """)

    def get(self, network, service):
        row = self.db.execute("SELECT * FROM choices WHERE network=? AND service=?", (network, service)).fetchone()
        return dict(row) if row else None

    def choose(self, network, service, route, ttl, evidence="http_reachable"):
        now = time.time()
        self.db.execute("INSERT OR REPLACE INTO choices VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)",
                        (network, service, route, now, now + ttl, now, evidence, now))
        self.db.commit()
        return self.get(network, service)

    def touch(self, network, service):
        self.db.execute("UPDATE choices SET last_used=? WHERE network=? AND service=?", (time.time(), network, service))
        self.db.commit()

    def failure(self, network, service):
        self.db.execute("UPDATE choices SET failures=failures+1 WHERE network=? AND service=?", (network, service))
        self.db.commit()

    def success(self, network, service):
        self.db.execute("UPDATE choices SET failures=0 WHERE network=? AND service=?", (network, service))
        self.db.commit()

    def invalidate(self, network, service):
        self.db.execute("UPDATE choices SET expires=0, failures=100 WHERE network=? AND service=?", (network, service))
        self.db.commit()

    def verified(self, network, service):
        self.db.execute("UPDATE choices SET verified=? WHERE network=? AND service=?", (time.time(), network, service))
        self.db.commit()

    def record(self, network, service, route, outcome, latency=0, status=None):
        self.db.execute("INSERT INTO attempts(at,network,service,route,outcome,latency_ms,status) VALUES(?,?,?,?,?,?,?)",
                        (time.time(), network, service, route, outcome, int(latency), status))
        self.db.execute("DELETE FROM attempts WHERE id <= (SELECT COALESCE(MAX(id),0)-2000 FROM attempts)")
        self.db.commit()

    def snapshot(self, network):
        return {
            "choices": [dict(r) for r in self.db.execute("SELECT * FROM choices WHERE network=?", (network,))],
            "attempts": [dict(r) for r in self.db.execute("SELECT * FROM attempts WHERE network=? ORDER BY id DESC LIMIT 40", (network,))],
        }

    def close(self):
        self.db.close()
