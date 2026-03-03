import os
from typing import Optional
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware

from src.api.auth import create_access_token, get_current_user, hash_password, verify_password
from src.api.db import db_cursor, get_db_connection
from src.api.models import (
    AuthResponse,
    ErrorResponse,
    LoginRequest,
    NoteCreateRequest,
    NoteResponse,
    NoteUpdateRequest,
    NotesListResponse,
    RegisterRequest,
    UserMeResponse,
)

openapi_tags = [
    {"name": "Health", "description": "Service health checks."},
    {"name": "Auth", "description": "User registration and login (JWT bearer auth)."},
    {"name": "Users", "description": "User self endpoints."},
    {"name": "Notes", "description": "CRUD, list and search for notes (per-user)."},
]

app = FastAPI(
    title="Notes Backend API",
    description=(
        "FastAPI backend for a notes application.\n\n"
        "Authentication:\n"
        "- Obtain a token via `POST /auth/register` or `POST /auth/login`\n"
        "- Use it as: `Authorization: Bearer <access_token>`\n\n"
        "Database:\n"
        "- Uses Postgres provisioned by the notes_database container\n"
        "- Reads the authoritative connection command from `notes_database/db_connection.txt`"
    ),
    version="1.0.0",
    openapi_tags=openapi_tags,
)

_allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").strip()
allow_origins = (
    [o.strip() for o in _allowed_origins.split(",") if o.strip()]
    if _allowed_origins != "*"
    else ["*"]
)

# CORS note:
# Browsers reject `Access-Control-Allow-Credentials: true` with a wildcard origin.
# We do not currently use cookies for auth (we use Bearer tokens), so default to
# credentials disabled unless explicit non-wildcard origins are configured.
allow_credentials = os.getenv("CORS_ALLOW_CREDENTIALS")
if allow_credentials is None:
    allow_credentials_bool = False if allow_origins == ["*"] else True
else:
    allow_credentials_bool = allow_credentials.strip().lower() in ("1", "true", "yes", "on")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=allow_credentials_bool,
    allow_methods=[m.strip() for m in os.getenv("ALLOWED_METHODS", "*").split(",")] if os.getenv("ALLOWED_METHODS") else ["*"],
    allow_headers=[h.strip() for h in os.getenv("ALLOWED_HEADERS", "*").split(",")] if os.getenv("ALLOWED_HEADERS") else ["*"],
    max_age=int(os.getenv("CORS_MAX_AGE", "3600")),
)


def _db_healthcheck() -> Optional[str]:
    """Return None if DB OK else an error string (for health endpoint)."""
    try:
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                cur.fetchone()
            conn.commit()
        finally:
            conn.close()
        return None
    except Exception as e:
        return str(e)


@app.get(
    "/",
    tags=["Health"],
    summary="Health check",
    description="Returns basic health status for the API.",
)
def health_check():
    """Entry point health check."""
    db_err = _db_healthcheck()
    payload = {"message": "Healthy"}
    if db_err:
        payload["db"] = {"status": "unhealthy", "error": db_err}
    else:
        payload["db"] = {"status": "healthy"}
    return payload


@app.get(
    "/docs/auth",
    tags=["Auth"],
    summary="Auth usage guide",
    description="Small usage guide for how to authenticate against this API.",
)
def auth_usage():
    """Return basic instructions for using bearer authentication."""
    return {
        "how_to_login": {
            "register": {"method": "POST", "path": "/auth/register"},
            "login": {"method": "POST", "path": "/auth/login"},
        },
        "how_to_call_protected_endpoints": {
            "header": "Authorization: Bearer <access_token>",
            "example": {"method": "GET", "path": "/users/me"},
        },
    }


def _get_user_by_email(email: str) -> Optional[dict]:
    with next(db_cursor()) as cur:
        cur.execute(
            """
            SELECT id, email, password_hash, created_at, updated_at, last_login_at
            FROM users
            WHERE lower(email) = lower(%s)
            """,
            (email,),
        )
        return cur.fetchone()


def _create_user(email: str, password_hash_str: str) -> dict:
    with next(db_cursor()) as cur:
        cur.execute(
            """
            INSERT INTO users (email, password_hash)
            VALUES (%s, %s)
            RETURNING id, email, created_at, updated_at, last_login_at
            """,
            (email, password_hash_str),
        )
        return cur.fetchone()


def _update_last_login(user_id: UUID) -> None:
    with next(db_cursor()) as cur:
        cur.execute("UPDATE users SET last_login_at = now() WHERE id = %s", (str(user_id),))


@app.post(
    "/auth/register",
    tags=["Auth"],
    summary="Register a new user",
    description="Create a user with email + password, returning an access token.",
    response_model=AuthResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Email already registered / invalid input."},
        500: {"model": ErrorResponse, "description": "Server error."},
    },
)
# PUBLIC_INTERFACE
def register(req: RegisterRequest):
    """Register a new user; returns JWT on success."""
    existing = _get_user_by_email(str(req.email))
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email is already registered")

    try:
        pw_hash = hash_password(req.password)
        user = _create_user(str(req.email), pw_hash)
    except Exception:
        # Most likely a unique constraint race or DB issue.
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create user")

    token = create_access_token(user_id=UUID(user["id"]), email=user["email"])
    return AuthResponse(access_token=token, user_id=UUID(user["id"]), email=user["email"])


@app.post(
    "/auth/login",
    tags=["Auth"],
    summary="Login",
    description="Login with email + password; returns an access token.",
    response_model=AuthResponse,
    responses={
        401: {"model": ErrorResponse, "description": "Invalid credentials."},
    },
)
# PUBLIC_INTERFACE
def login(req: LoginRequest):
    """Login and return a JWT bearer token."""
    user = _get_user_by_email(str(req.email))
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    _update_last_login(UUID(user["id"]))
    token = create_access_token(user_id=UUID(user["id"]), email=user["email"])
    return AuthResponse(access_token=token, user_id=UUID(user["id"]), email=user["email"])


@app.get(
    "/users/me",
    tags=["Users"],
    summary="Get current user",
    description="Returns the currently authenticated user's profile.",
    response_model=UserMeResponse,
    responses={401: {"model": ErrorResponse, "description": "Unauthorized."}},
)
# PUBLIC_INTERFACE
def me(current_user: dict = Depends(get_current_user)):
    """Return current user profile."""
    return UserMeResponse(
        id=UUID(current_user["id"]),
        email=current_user["email"],
        created_at=current_user["created_at"],
        updated_at=current_user["updated_at"],
        last_login_at=current_user.get("last_login_at"),
    )


def _note_row_to_model(row: dict) -> NoteResponse:
    return NoteResponse(
        id=UUID(row["id"]),
        user_id=UUID(row["user_id"]),
        title=row["title"],
        content=row["content"],
        is_archived=bool(row["is_archived"]),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@app.post(
    "/notes",
    tags=["Notes"],
    summary="Create note",
    description="Create a note for the authenticated user.",
    response_model=NoteResponse,
    responses={401: {"model": ErrorResponse, "description": "Unauthorized."}},
)
# PUBLIC_INTERFACE
def create_note(req: NoteCreateRequest, current_user: dict = Depends(get_current_user)):
    """Create a new note for the current user."""
    with next(db_cursor()) as cur:
        cur.execute(
            """
            INSERT INTO notes (user_id, title, content, is_archived)
            VALUES (%s, %s, %s, %s)
            RETURNING id, user_id, title, content, is_archived, created_at, updated_at
            """,
            (current_user["id"], req.title, req.content, req.is_archived),
        )
        row = cur.fetchone()
    return _note_row_to_model(row)


@app.get(
    "/notes",
    tags=["Notes"],
    summary="List notes",
    description="List notes for the authenticated user, optionally filtering archived notes.",
    response_model=NotesListResponse,
)
# PUBLIC_INTERFACE
def list_notes(
    current_user: dict = Depends(get_current_user),
    q: Optional[str] = Query(None, description="Optional search query (full-text)."),
    is_archived: Optional[bool] = Query(None, description="Optional archived filter."),
    limit: int = Query(20, ge=1, le=100, description="Page size."),
    offset: int = Query(0, ge=0, description="Offset into results."),
):
    """
    List notes (with optional full-text search) for current user.

    Search behavior:
      - If q is provided, performs full-text search over title+content (english).
      - Results are always scoped to the authenticated user.
    """
    params = {"user_id": current_user["id"], "limit": limit, "offset": offset}
    where_clauses = ["user_id = %(user_id)s"]
    order_by = "updated_at DESC"

    if is_archived is not None:
        where_clauses.append("is_archived = %(is_archived)s")
        params["is_archived"] = is_archived

    if q:
        # Use the generated tsvector column + plainto_tsquery for user-friendly search.
        where_clauses.append("search_document @@ plainto_tsquery('english', %(q)s)")
        params["q"] = q
        order_by = "ts_rank(search_document, plainto_tsquery('english', %(q)s)) DESC, updated_at DESC"

    where_sql = " AND ".join(where_clauses)

    with next(db_cursor()) as cur:
        cur.execute(
            f"""
            SELECT COUNT(*)::int AS total
            FROM notes
            WHERE {where_sql}
            """,
            params,
        )
        total_row = cur.fetchone()
        total = int(total_row["total"]) if total_row else 0

        cur.execute(
            f"""
            SELECT id, user_id, title, content, is_archived, created_at, updated_at
            FROM notes
            WHERE {where_sql}
            ORDER BY {order_by}
            LIMIT %(limit)s OFFSET %(offset)s
            """,
            params,
        )
        rows = cur.fetchall() or []

    return NotesListResponse(items=[_note_row_to_model(r) for r in rows], total=total, limit=limit, offset=offset)


@app.get(
    "/notes/{note_id}",
    tags=["Notes"],
    summary="Get note",
    description="Fetch a single note by ID (must belong to the authenticated user).",
    response_model=NoteResponse,
    responses={404: {"model": ErrorResponse, "description": "Not found."}},
)
# PUBLIC_INTERFACE
def get_note(note_id: UUID, current_user: dict = Depends(get_current_user)):
    """Get a single note by ID for the current user."""
    with next(db_cursor()) as cur:
        cur.execute(
            """
            SELECT id, user_id, title, content, is_archived, created_at, updated_at
            FROM notes
            WHERE id = %s AND user_id = %s
            """,
            (str(note_id), current_user["id"]),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return _note_row_to_model(row)


@app.patch(
    "/notes/{note_id}",
    tags=["Notes"],
    summary="Update note",
    description="Update note fields (partial update). Note must belong to the authenticated user.",
    response_model=NoteResponse,
    responses={404: {"model": ErrorResponse, "description": "Not found."}},
)
# PUBLIC_INTERFACE
def update_note(note_id: UUID, req: NoteUpdateRequest, current_user: dict = Depends(get_current_user)):
    """Update a note for the current user (partial)."""
    if req.title is None and req.content is None and req.is_archived is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    set_parts = []
    params = {"note_id": str(note_id), "user_id": current_user["id"]}

    if req.title is not None:
        set_parts.append("title = %(title)s")
        params["title"] = req.title
    if req.content is not None:
        set_parts.append("content = %(content)s")
        params["content"] = req.content
    if req.is_archived is not None:
        set_parts.append("is_archived = %(is_archived)s")
        params["is_archived"] = req.is_archived

    set_sql = ", ".join(set_parts)

    with next(db_cursor()) as cur:
        cur.execute(
            f"""
            UPDATE notes
            SET {set_sql}
            WHERE id = %(note_id)s AND user_id = %(user_id)s
            RETURNING id, user_id, title, content, is_archived, created_at, updated_at
            """,
            params,
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return _note_row_to_model(row)


@app.delete(
    "/notes/{note_id}",
    tags=["Notes"],
    summary="Delete note",
    description="Delete a note by ID (must belong to the authenticated user).",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={404: {"model": ErrorResponse, "description": "Not found."}},
)
# PUBLIC_INTERFACE
def delete_note(note_id: UUID, current_user: dict = Depends(get_current_user)):
    """Delete a note for the current user."""
    with next(db_cursor()) as cur:
        cur.execute(
            "DELETE FROM notes WHERE id = %s AND user_id = %s RETURNING id",
            (str(note_id), current_user["id"]),
        )
        row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Note not found")
    return None
