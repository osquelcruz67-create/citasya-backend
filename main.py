"""
CitasYa Backend Patch v3.1
Maneja las rutas admin directamente y proxea todo lo demás al backend original.
"""

import os
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Header, Query, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

# ------------------------------------------------------------------------------
# Configuración
# ------------------------------------------------------------------------------
MONGO_URL    = os.environ.get("MONGO_URL", os.environ.get("MONGODB_URL", ""))
DB_NAME      = os.environ.get("DB_NAME", "citasya")
PORT         = int(os.environ.get("PORT", "8000"))
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "")  # URL del backend original

ADMIN_EMAILS    = {"osquelcruz67@gmail.com", "osquelcruz55@gmail.com"}
_ADMIN_EMAILS_LC = {e.lower() for e in ADMIN_EMAILS}

RESET_SECRET = os.environ.get("RESET_SECRET", "citasya-reset-2026")

# ------------------------------------------------------------------------------
# App
# ------------------------------------------------------------------------------
app = FastAPI(title="CitasYa Backend Patch", version="3.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client: Optional[AsyncIOMotorClient] = None
db = None
http_client: Optional[httpx.AsyncClient] = None


@app.on_event("startup")
async def startup():
    global client, db, http_client
    if MONGO_URL:
        client = AsyncIOMotorClient(MONGO_URL)
        db = client[DB_NAME]
        print(f"[patch] MongoDB conectado: {DB_NAME}")
    if UPSTREAM_URL:
        http_client = httpx.AsyncClient(base_url=UPSTREAM_URL, timeout=30.0)
        print(f"[patch] Upstream: {UPSTREAM_URL}")


@app.on_event("shutdown")
async def shutdown():
    if client:
        client.close()
    if http_client:
        await http_client.aclose()


# ------------------------------------------------------------------------------
# Helpers de auth
# ------------------------------------------------------------------------------
def _is_admin(user: Optional[dict]) -> bool:
    if not user:
        return False
    email = (user.get("email") or "").strip().lower()
    if email in _ADMIN_EMAILS_LC:
        return True
    return user.get("role") == "admin" or user.get("is_admin") is True


async def _require_admin(authorization: Optional[str] = Header(None)):
    if not authorization:
        raise HTTPException(status_code=401, detail="No autorizado")
    token = authorization.removeprefix("Bearer ").strip()
    user = await _verify_token(token)
    if not _verify_token or not _is_admin(user):
        raise HTTPException(status_code=403, detail="Acceso denegado")
    return user


async def _verify_token(token: str) -> Optional[dict]:
    try:
        if http_client:
            resp = await http_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return None


# ------------------------------------------------------------------------------
# Rutas admin/users (manejadas directamente)
# ------------------------------------------------------------------------------
@app.get("/api/admin/users")
async def list_users(
    skip:   int = Query(0, ge=0),
    limit:  int = Query(50, ge=1, le=1000),
    search: str = Query(""),
    _user=Depends(_require_admin),
):
    query = {}
    if search:
        rx = {"$regex": re.escape(search), "$options": "i"}
        query["$or"] = [{"display_name": rx}, {"username": rx}, {"email": rx}, {"name": rx}]
    total  = await db.users.count_documents(query)
    cursor = db.users.find(query, {"_id": 0, "password_hash": 0}).sort("created_at", -1).skip(skip).limit(limit)
    users  = [_serialize(u) for u in await cursor.to_list(length=limit)]
    return {"total": total, "skip": skip, "limit": limit, "users": users}


@app.get("/api/admin/stats")
async def get_stats(_user=Depends(_require_admin)):
    total_users   = await db.users.count_documents({})
    active_users  = await db.users.count_documents({"status": "active"})
    total_videos  = await db.videos.count_documents({})
    return {"total_users": total_users, "active_users": active_users, "total_videos": total_videos}


def _serialize(doc: dict) -> dict:
    return {k: str(v) if isinstance(v, ObjectId) else v for k, v in doc.items()}


# ------------------------------------------------------------------------------
# Endpoint temporal: borrar usuario por email (solo para admin emails)
# ------------------------------------------------------------------------------
@app.delete("/api/debug/delete-user")
async def delete_user(email: str = Query(...), secret: str = Query(...)):
    if secret != RESET_SECRET:
        raise HTTPException(status_code=403, detail="Acceso denegado")
    if email.lower() not in _ADMIN_EMAILS_LC:
        raise HTTPException(status_code=403, detail="Solo para cuentas admin")
    if not db:
        raise HTTPException(status_code=503, detail="MongoDB no configurado")
    result = await db.users.delete_one({"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}})
    return {"deleted": result.deleted_count, "email": email}


@app.get("/api/debug/check-user")
async def check_user(email: str = Query(...), secret: str = Query(...)):
    if secret != RESET_SECRET:
        raise HTTPException(status_code=403, detail="Acceso denegado")
    if not db:
        raise HTTPException(status_code=503, detail="MongoDB no configurado")
    user = await db.users.find_one(
        {"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}},
        {"_id": 0, "password_hash": 0}
    )
    return {"found": user is not None, "user": user}


# ------------------------------------------------------------------------------
# Catch-all proxy
# ------------------------------------------------------------------------------
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy(request: Request, path: str):
    if not http_client:
        raise HTTPException(status_code=503, detail="No upstream configured")
    try:
        body = await request.body()
        headers = dict(request.headers)
        headers.pop("host", None)
        resp = await http_client.request(
            method=request.method,
            url=f"/{path}",
            params=dict(request.query_params),
            headers=headers,
            content=body,
        )
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            headers=dict(resp.headers),
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
