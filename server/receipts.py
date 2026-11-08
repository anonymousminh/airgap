"""Containment Receipts: canonical JSON (integers only) -> Ed25519 signature -> hash-chained ledger."""
import base64, hashlib, json, sqlite3, threading
from datetime import datetime, timezone
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from . import settings


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _assert_no_floats(o):
    if isinstance(o, float):
        raise ValueError("floats are not allowed in receipts")
    if isinstance(o, dict):
        for v in o.values(): _assert_no_floats(v)
    elif isinstance(o, list):
        for v in o: _assert_no_floats(v)


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Ledger:
    def __init__(self):
        settings.STATE_DIR.mkdir(parents=True, exist_ok=True)
        if settings.KEY_PATH.exists():
            self.sk = SigningKey(settings.KEY_PATH.read_bytes())
        else:
            self.sk = SigningKey.generate()
            settings.KEY_PATH.write_bytes(bytes(self.sk)); settings.KEY_PATH.chmod(0o600)
        self.pub_b64 = base64.b64encode(bytes(self.sk.verify_key)).decode()
        self.db = sqlite3.connect(settings.DB_PATH, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""CREATE TABLE IF NOT EXISTS receipts(
            seq INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT UNIQUE, prev_hash TEXT,
            run_id TEXT, kind TEXT, body TEXT)""")
        self.db.commit()
        self.lock = threading.Lock()

    def head(self):
        row = self.db.execute("SELECT seq, hash FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
        return {"seq": row[0] if row else 0, "hash": row[1] if row else None}

    def issue(self, body: dict) -> dict:
        with self.lock:
            prev = self.head()["hash"]
            body = {**body, "receipt_version": 1, "issued_at": now_iso(), "prev_receipt_hash": prev or "genesis"}
            _assert_no_floats(body)
            msg = canonical(body)
            sig = base64.b64encode(self.sk.sign(msg).signature).decode()
            h = "sha256:" + sha256_hex(msg + sig.encode())
            full = {**body, "receipt_hash": h, "signature_ed25519": sig}
            self.db.execute("INSERT INTO receipts(hash, prev_hash, run_id, kind, body) VALUES (?,?,?,?,?)",
                            (h, prev or "genesis", body.get("run_id"), body.get("kind"), json.dumps(full)))
            self.db.commit()
            return full

    def verify(self, receipt: dict) -> dict:
        try:
            sig = receipt["signature_ed25519"]; claimed = receipt["receipt_hash"]
            body = {k: v for k, v in receipt.items() if k not in ("signature_ed25519", "receipt_hash")}
            msg = canonical(body)
            VerifyKey(base64.b64decode(self.pub_b64)).verify(msg, base64.b64decode(sig))
            sig_ok = True
        except (BadSignatureError, KeyError, ValueError, TypeError):
            return {"valid": False, "signature_ok": False, "chain_ok": False, "reason": "signature does not match contents"}
        hash_ok = claimed == "sha256:" + sha256_hex(msg + sig.encode())
        row = self.db.execute("SELECT prev_hash FROM receipts WHERE hash=?", (claimed,)).fetchone()
        prev = body.get("prev_receipt_hash")
        chain_ok = bool(row) and row[0] == prev and (prev == "genesis" or
                   self.db.execute("SELECT 1 FROM receipts WHERE hash=?", (prev,)).fetchone() is not None)
        return {"valid": sig_ok and hash_ok, "signature_ok": sig_ok, "chain_ok": chain_ok,
                "in_ledger": bool(row), "reason": "ok" if sig_ok and hash_ok else "hash mismatch"}

    def recent(self, n: int = 12) -> list[dict]:
        rows = self.db.execute("SELECT seq, hash, prev_hash, run_id, kind, body FROM receipts ORDER BY seq DESC LIMIT ?", (n,)).fetchall()
        out = []
        for seq, h, prev, rid, kind, body in rows:
            b = json.loads(body)
            c = b.get("containment", {})
            out.append({"seq": seq, "hash": h, "prev_hash": prev, "run_id": rid, "kind": kind,
                        "issued_at": b.get("issued_at"), "attack_id": b.get("task", {}).get("attack_id"),
                        "outcome": c.get("outcome", "analysis")})
        return out

    def get(self, run_id: str):
        row = self.db.execute("SELECT body FROM receipts WHERE run_id=? ORDER BY seq DESC LIMIT 1", (run_id,)).fetchone()
        return json.loads(row[0]) if row else None
