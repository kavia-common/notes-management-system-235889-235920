import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

import psycopg


@dataclass(frozen=True)
class DbConfig:
    """Parsed DB connection information for psycopg connections."""
    dsn: str


def _default_db_connection_file() -> Path:
    """
    Compute the most likely location of notes_database/db_connection.txt.

    In this monorepo, the database container may live in a *different* sibling workspace
    than the backend (common in preview environments). We therefore:

    1) First try the historical monorepo layout:
         <repo>/<backend_workspace>/notes_database/db_connection.txt
    2) If not found, scan sibling workspaces for:
         <repo>/notes-management-system-*/notes_database/db_connection.txt

    This avoids hard-coding DB env vars while remaining robust across preview layouts.
    """
    repo_root = Path(__file__).resolve().parents[4]

    # 1) Historical layout (sibling folder inside same workspace root)
    candidate = Path(__file__).resolve().parents[3] / "notes_database" / "db_connection.txt"
    if candidate.exists():
        return candidate

    # 2) Preview layout: separate workspace directories
    #    e.g. notes-management-system-*/notes_database/db_connection.txt
    for db_file in repo_root.glob("notes-management-system-*/notes_database/db_connection.txt"):
        if db_file.exists():
            return db_file

    # Fall back to the original candidate path (so error messages are deterministic)
    return candidate


def _parse_psql_cmd_to_dsn(psql_cmd: str) -> str:
    """
    Convert 'psql postgresql://user:pass@host:port/db' into a DSN psycopg can use.

    Raises:
        ValueError: if the file format doesn't match expected pattern.
    """
    psql_cmd = psql_cmd.strip()
    m = re.match(r"^psql\s+(postgres(?:ql)?://\S+)\s*$", psql_cmd)
    if not m:
        raise ValueError("db_connection.txt format unexpected; expected: 'psql postgresql://...'")
    return m.group(1)


# PUBLIC_INTERFACE
def load_db_config(db_connection_file: Optional[str] = None) -> DbConfig:
    """
    Load database connection configuration from the authoritative db_connection.txt.

    Args:
        db_connection_file: Optional override path. If omitted, uses the convention path.

    Returns:
        DbConfig with a DSN ready for psycopg.connect(...)

    Raises:
        FileNotFoundError: if db_connection.txt cannot be found.
        ValueError: if contents are not in expected format.
    """
    path = Path(db_connection_file) if db_connection_file else _default_db_connection_file()
    raw = path.read_text(encoding="utf-8")
    dsn = _parse_psql_cmd_to_dsn(raw)
    return DbConfig(dsn=dsn)


# PUBLIC_INTERFACE
def get_db_connection() -> psycopg.Connection:
    """
    Open a new psycopg connection to Postgres using db_connection.txt.

    Returns:
        psycopg.Connection: an open connection (caller should close).

    Notes:
        - We prefer reading db_connection.txt to avoid hardcoding DB env vars.
    """
    cfg = load_db_config(os.getenv("DB_CONNECTION_FILE"))
    return psycopg.connect(cfg.dsn)


def db_cursor(dict_rows: bool = True) -> Iterator[psycopg.Cursor]:
    """
    Context manager-yield style helper for a DB cursor, committing on success.

    dict_rows=True uses psycopg.rows.dict_row to return dict-like rows.
    """
    row_factory = psycopg.rows.dict_row if dict_rows else None
    conn = get_db_connection()
    try:
        with conn.cursor(row_factory=row_factory) as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
