# Note: AI generated file. Hope it works.
import hashlib
import os
import pickle
import re
import sqlite3
import textwrap
import time
from functools import wraps
from typing import Callable, Optional, ParamSpec, TypeVar, Union, cast

from loguru import logger

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


def _parse_ttl_safe(ttl: Optional[DurationInput]) -> float:
    try:
        return _parse_ttl(ttl) or 0
    except Exception:
        return 0


class LazyDb:
    _cache: dict[tuple[str, str], sqlite3.Connection] = {}

    @classmethod
    def _get_db(cls, dbpath: str, tablename: str) -> sqlite3.Connection:
        # Use check_same_thread=False to allow use across threads (simple use-case)
        db = sqlite3.connect(dbpath, timeout=30, isolation_level=None, check_same_thread=False)

        qs = f"""
        CREATE TABLE IF NOT EXISTS {tablename} (
            func TEXT NOT NULL,
            key TEXT NOT NULL,
            ts REAL NOT NULL,
            value BLOB NOT NULL,
            PRIMARY KEY(func, key)
        );
        """
        db.execute(textwrap.dedent(qs).strip())
        db.execute(f"CREATE INDEX IF NOT EXISTS idx_{tablename}_func_ts ON {tablename}(func, ts)")
        return db

    @classmethod
    def getdb(cls, dbpath: str, tablename: str) -> sqlite3.Connection:
        key = (dbpath, tablename)
        if key not in cls._cache:
            cls._cache[key] = cls._get_db(dbpath, tablename)

        return cls._cache[key]

    def __init__(self, dbpath: str, tablename: str):
        self.dbpath = dbpath
        self.tablename = tablename

    def get_cache(self, func: str, key: str, expire_before: float) -> Optional[bytes]:
        db = self.getdb(self.dbpath, self.tablename)

        qs = f"SELECT value, ts FROM {self.tablename} WHERE func=? AND key=? AND ts>=?"
        rs = db.execute(qs, (func, key, expire_before)).fetchone()
        if rs is not None:
            val_blob, ts_val = rs
            return val_blob

        return None

    def set_cache(self, func: str, key: str, val_blob: bytes) -> None:
        db = self.getdb(self.dbpath, self.tablename)

        qs = f"INSERT OR REPLACE INTO {self.tablename} (func, key, ts, value) VALUES (?,?,?,?)"
        db.execute(qs, (func, key, time.time(), val_blob))


def _sanitize(obj):
    try:
        return pickle.dumps(obj)  # pickled directly
    except Exception:
        return None


def _to_args_blob(args: tuple, kwargs: dict) -> bytes:
    safe_args = [_sanitize(a) for a in args]
    safe_kwargs = {k: _sanitize(v) for k, v in kwargs.items()}
    # print("args", safe_args)
    # print("kwargs", safe_kwargs)
    return pickle.dumps((safe_args, safe_kwargs), protocol=5)


def sqlcache(
    _func: Optional[Callable[P, T]] = None,
    *,
    ttl: Optional[DurationInput] = None,
    dbpath: str = ".cache/cache.sqlite3",
    table: str = "cache",
) -> Callable[[Callable[P, T]], Callable[P, T]] | Callable[P, T]:
    ttl_sec = _parse_ttl_safe(ttl)
    os.makedirs(os.path.dirname(dbpath), exist_ok=True)

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            if ttl_sec <= 0:  # if ttl is zero or invalid, do not cache
                return func(*args, **kwargs)

            try:
                arg_blob = _to_args_blob(args, kwargs)
            except Exception as e:
                logger.warning(f"sqlcache: cannot pickle args for {func.__name__}: {type(e)}.")
                return func(*args, **kwargs)

            db = LazyDb(dbpath, table)
            key = hashlib.sha256(arg_blob).hexdigest()
            expire_before = time.time() - ttl_sec

            try:
                val_blob = db.get_cache(func.__name__, key, expire_before)
                if val_blob is not None:
                    return cast(T, pickle.loads(val_blob))
            except Exception as e:  # DB read failures OR unpickle failures -> compute fresh
                logger.warning(f"sqlcache: cannot read cache for {func.__name__}: {type(e)}.")

            rs = func(*args, **kwargs)

            try:
                val_blob = pickle.dumps(rs, protocol=5)
                db.set_cache(func.__name__, key, val_blob)
            except Exception as e:
                logger.warning(f"sqlcache: cannot write cache for {func.__name__}: {type(e)}.")

            return rs

        return wrapper

    # allow both @sqlcache and @sqlcache(...) usage
    if _func is not None and callable(_func):
        return decorator(_func)

    return decorator
