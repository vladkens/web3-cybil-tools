# Note: AI generated file. Hope it works.
import hashlib
import os
import pickle
import re
import sqlite3
import time
from functools import wraps
from typing import Callable, Optional, ParamSpec, TypeVar, Union, cast

P = ParamSpec("P")
T = TypeVar("T")

DurationInput = Union[str, int, float]

_UNIT_MULTIPLIERS = {
    "s": 1,
    "m": 60,
    "h": 60 * 60,
    "d": 60 * 60 * 24,
    "w": 60 * 60 * 24 * 7,
}


def _parse_ttl(ttl: Optional[DurationInput]) -> Optional[float]:
    if ttl is None:
        return None

    if isinstance(ttl, (int, float)):
        return float(ttl)

    ttl = ttl.strip().lower()
    if ttl == "":
        return None

    # If it's just a number, treat as seconds
    if ttl.replace(".", "", 1).isdigit():
        return float(ttl)

    # Allow composite sequences number+unit
    total = 0.0
    pos = 0
    pattern = re.compile(r"(\d+(?:\.\d*)?)([smhdw])")
    for m in pattern.finditer(ttl):
        if m.start() != pos:
            raise ValueError(f"Invalid TTL segment at position {pos} in '{ttl}'")
        num = float(m.group(1))
        unit = m.group(2)
        total += num * _UNIT_MULTIPLIERS[unit]
        pos = m.end()

    if pos != len(ttl):
        raise ValueError(f"Invalid TTL specification: '{ttl}'")

    return total


def sqlcache(
    _func: Optional[Callable[P, T]] = None,
    *,
    ttl: Optional[DurationInput] = None,
    db_path: str = ".cache/cache.sqlite3",
    table: str = "cache",
) -> Callable[[Callable[P, T]], Callable[P, T]] | Callable[P, T]:
    try:
        ttl_seconds = _parse_ttl(ttl)
    except Exception:
        ttl_seconds = None

    # Ensure directory for DB exists
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)

    def _get_conn() -> sqlite3.Connection:
        # Use check_same_thread=False to allow use across threads (simple use-case)
        return sqlite3.connect(db_path, timeout=30, isolation_level=None, check_same_thread=False)

    try:
        with _get_conn() as conn:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {table} (\n"
                "  func TEXT NOT NULL,\n"
                "  key TEXT NOT NULL,\n"
                "  ts REAL NOT NULL,\n"
                "  value BLOB NOT NULL,\n"
                "  PRIMARY KEY(func, key)\n"
                ")"
            )
            conn.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_func_ts ON {table}(func, ts)")
    except Exception:
        # If DB cannot be initialized we'll just operate uncached.
        pass

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            if ttl_seconds is not None and ttl_seconds <= 0:
                return func(*args, **kwargs)

            try:
                arg_blob = pickle.dumps((args, kwargs), protocol=5)
            except Exception:
                return func(*args, **kwargs)

            key = hashlib.sha256(arg_blob).hexdigest()

            # Attempt read
            if ttl_seconds is not None:
                expire_before = time.time() - ttl_seconds
            else:
                expire_before = None

            try:
                with _get_conn() as conn:
                    if expire_before is not None:
                        # Remove expired entries for this func lazily (optional cleanup)
                        try:
                            conn.execute(
                                f"DELETE FROM {table} WHERE func=? AND ts<?",
                                (func.__name__, expire_before),
                            )
                        except Exception:
                            pass
                    row = conn.execute(
                        f"SELECT value, ts FROM {table} WHERE func=? AND key=?",
                        (func.__name__, key),
                    ).fetchone()
                    if row is not None:
                        value_blob, ts_val = row
                        if expire_before is None or ts_val >= expire_before:
                            try:
                                return cast(T, pickle.loads(value_blob))
                            except Exception:
                                pass
            except Exception:
                pass  # DB read failures -> compute fresh

            # Compute fresh
            result = func(*args, **kwargs)

            # Write
            try:
                value_blob = pickle.dumps(result, protocol=5)
                with _get_conn() as conn:
                    conn.execute(
                        f"INSERT OR REPLACE INTO {table} (func, key, ts, value) VALUES (?,?,?,?)",
                        (func.__name__, key, time.time(), value_blob),
                    )
            except Exception:
                pass

            return result

        return wrapper

    if _func is not None and callable(_func):
        return decorator(_func)

    return decorator
