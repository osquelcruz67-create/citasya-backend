"""
CitasYa Backend Patch v3.0
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

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
MONGO_URL    = os.environ.get("MONGO_URL", os.environ.get("MONGODB_URL", ""))
DB_NAME      = os.environ.get("DB_NAME", "citasya")
PORT         = int(os.environ.get("PORT", "8000"))
UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "")  # URL del backend original

ADMIN_EMAILS    = {"osquelcruz67@gmail.com", "osquelcruz55@gmail.com"}
_ADMIN_EMAILS_LC = {e.lower() for e in ADMIN_EMAILS}

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="CitasYa Backend Patch", version="3.0")
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


# ---------------------------------------------------------------------------
# Helpers de auth
# ---------------------------------------------------------------------------
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
    if not token or db is None:
        raise HTTPException(status_code=401, detail="Sesión inválida")
    session = await db.user_sessions.find_one({"session_token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Sesión inválida")
    user = await db.users.find_one({"user_id": session["user_id"]})
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if not _is_admin(user):
        raise HTTPException(status_code=403, detail="Acceso denegado — se requiere admin")
    return user


def _serialize(doc: dict) -> dict:
    return {k: str(v) if isinstance(v, ObjectId) else v for k, v in doc.items()}


# ---------------------------------------------------------------------------
# Rutas admin/users (manejadas directamente)
# ---------------------------------------------------------------------------
@app.get("/api/admin/users")
async def list_users(
    skip:   int = Query(0, ge=0),
    limit:  int = Query(50, ge=1, le=200),
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


@app.get("/api/admin/users/{user_id}")
async def get_user(user_id: str, _user=Depends(_require_admin)):
    u = await db.users.find_one({"user_id": user_id}, {"_id": 0, "password_hash": 0})
    if not u:
        raise HTTPException(404, "Usuario no encontrado")
    u = _serialize(u)
    u["stats"] = {
        "followers":  await db.follows.count_documents({"following_id": user_id}),
        "following":  await db.follows.count_documents({"follower_id":  user_id}),
        "videos":     await db.videos.count_documents({"user_id": user_id}),
        "posts":      await db.posts.count_documents({"user_id": user_id}),
    }
    return u


@app.patch("/api/admin/users/{user_id}")
async def update_user(user_id: str, body: dict, _user=Depends(_require_admin)):
    allowed = {"display_name","username","bio","profile_image","role","is_admin","is_verified","is_banned","email","phone","name"}
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        raise HTTPException(400, "Sin campos válidos")
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    res = await db.users.update_one({"user_id": user_id}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(404, "Usuario no encontrado")
    return {"ok": True, "updated": res.modified_count, "fields": list(updates.keys())}


@app.delete("/api/admin/users/{user_id}")
async def delete_user(user_id: str, _user=Depends(_require_admin)):
    existing = await db.users.find_one({"user_id": user_id})
    if not existing:
        raise HTTPException(404, "Usuario no encontrado")
    if _is_admin(existing):
        raise HTTPException(403, "No se puede eliminar una cuenta admin")
    deleted = {
        "user":                  (await db.users.delete_one({"user_id": user_id})).deleted_count,
        "sessions":              (await db.user_sessions.delete_many({"user_id": user_id})).deleted_count,
        "videos":                (await db.videos.delete_many({"user_id": user_id})).deleted_count,
        "posts":                 (await db.posts.delete_many({"user_id": user_id})).deleted_count,
        "follows_as_follower":   (await db.follows.delete_many({"follower_id": user_id})).deleted_count,
        "follows_as_following":  (await db.follows.delete_many({"following_id": user_id})).deleted_count,
    }
    return {"success": True, "deleted_user_id": user_id, "deleted": deleted}


# ---------------------------------------------------------------------------
# Regenerar thumbnails (manejado directamente)
# ---------------------------------------------------------------------------
@app.post("/api/admin/regenerate-thumbnails")
async def regenerate_thumbnails(_user=Depends(_require_admin)):
    """Recorre todos los videos sin thumbnail y les asigna uno desde video_url."""
    updated = 0
    query = {"$or": [
        {"thumbnail_url": None},
        {"thumbnail_url": ""},
        {"thumbnail_url": {"$exists": False}},
    ]}
    async for video in db.videos.find(query):
        video_url = video.get("video_url") or video.get("url") or ""
        if video_url:
            await db.videos.update_one(
                {"_id": video["_id"]},
                {"$set": {
                    "thumbnail_url": video_url,
                    "thumbnail_updated_at": datetime.now(timezone.utc).isoformat(),
                }},
            )
            updated += 1
    return {"ok": True, "updated": updated, "message": f"Se corrigieron {updated} miniaturas"}


# ---------------------------------------------------------------------------
# Health check propio
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "3.0-patch", "upstream": UPSTREAM_URL or "none"}


# ---------------------------------------------------------------------------
# Proxy general — todo lo demás va al backend original
# ---------------------------------------------------------------------------
@app.api_route("/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"])
async def proxy_all(path: str, request: Request):
    if not UPSTREAM_URL or not http_client:
        raise HTTPException(503, detail="Upstream no configurado. Contacta al administrador.")
    url = f"/{path}"
    qs  = request.url.query
    if qs:
        url += f"?{qs}"
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    body = await request.body()
    resp = await http_client.request(
        method=request.method,
        url=url,
        headers=fwd_headers,
        content=body,
    )
    resp_headers = {k: v for k, v in resp.headers.items()
                    if k.lower() not in ("transfer-encoding", "content-encoding")}
    return Response(content=resp.content, status_code=resp.status_code, headers=resp_headers)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT)
