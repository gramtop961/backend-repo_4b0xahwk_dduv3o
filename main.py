import os
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

from database import db, create_document, get_documents

app = FastAPI(title="School Club Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utilities

def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _oid(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc = dict(doc)
    if doc.get("_id") is not None:
        doc["id"] = str(doc.pop("_id"))
    # convert datetimes to iso
    for k, v in list(doc.items()):
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


# Models
class RegisterBody(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "student"  # only admin can create admin/spoc


class LoginBody(BaseModel):
    email: EmailStr
    password: str


class PostBody(BaseModel):
    title: str
    content: str
    visibility: str = "public"  # public | members
    tags: List[str] = []


class ResourceBody(BaseModel):
    title: str
    description: Optional[str] = None
    url: Optional[str] = None
    file_url: Optional[str] = None
    category: Optional[str] = None
    tags: List[str] = []


class NotificationBody(BaseModel):
    user_id: Optional[str] = None  # None => broadcast
    title: str
    message: str
    type: str = "info"  # info|success|warning|error
    link: Optional[str] = None


# Auth helpers
async def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ", 1)[1]
    session = db["session"].find_one({"token": token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    # check expiry if present
    if session.get("expires_at"):
        try:
            if datetime.fromisoformat(session["expires_at"]) < _now():
                raise HTTPException(status_code=401, detail="Session expired")
        except Exception:
            pass
    user = db["user"].find_one({"_id": session["user_id"]})
    # In some environments, user_id may be stored as string, handle both
    if not user:
        from bson import ObjectId
        try:
            user = db["user"].find_one({"_id": ObjectId(str(session["user_id"]))})
        except Exception:
            user = None
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return _oid(user)


def require_role(user: Dict[str, Any], allowed: List[str]):
    if user.get("role") not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient permissions")


@app.get("/")
def root():
    return {"message": "School Club Management API is running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"⚠️ Error: {str(e)[:100]}"
    return response


# Demo bootstrap for quick testing
@app.post("/demo/bootstrap")
def bootstrap_demo():
    from bson import ObjectId
    created: List[str] = []
    users = [
        {"name": "Admin", "email": "admin@club.edu", "password": "admin123", "role": "admin"},
        {"name": "SPOC", "email": "spoc@club.edu", "password": "spoc123", "role": "spoc"},
        {"name": "Student", "email": "student@club.edu", "password": "student123", "role": "student"},
    ]
    for u in users:
        existing = db["user"].find_one({"email": u["email"]})
        if not existing:
            uid = db["user"].insert_one({
                "name": u["name"],
                "email": u["email"],
                "password_hash": _hash_password(u["password"]),
                "role": u["role"],
                "is_active": True,
                "created_at": _now(),
                "updated_at": _now(),
            }).inserted_id
            created.append(str(uid))
    # sample post/resource
    if db["post"].count_documents({}) == 0:
        db["post"].insert_one({
            "title": "Welcome to the Club!",
            "content": "This is the official club portal.",
            "author_id": None,
            "author_name": "Admin",
            "visibility": "public",
            "tags": ["welcome"],
            "created_at": _now(),
            "updated_at": _now(),
        })
    if db["resource"].count_documents({}) == 0:
        db["resource"].insert_one({
            "title": "Getting Started Guide",
            "description": "Learn how to use the portal and participate in events.",
            "url": "https://example.com/guide",
            "created_by": "system",
            "created_by_name": "Admin",
            "tags": ["guide", "onboarding"],
            "created_at": _now(),
            "updated_at": _now(),
        })
    return {"created_users": created, "message": "Demo accounts ready", "credentials": users}


# Auth routes
@app.post("/auth/register")
def register(body: RegisterBody, user: Optional[Dict[str, Any]] = Depends(lambda: None), authorization: Optional[str] = Header(None)):
    # Only students can self-register. Admin token required for spoc/admin
    requested_role = body.role.lower()
    if requested_role in ("spoc", "admin"):
        # must have admin token
        if not authorization:
            raise HTTPException(status_code=403, detail="Admin token required to create SPOC/Admin")
        current = Depends(get_current_user)
        # FastAPI quirk: call dependency manually when using Header above
        try:
            current_user = get_current_user.__wrapped__(authorization)  # type: ignore
        except Exception:
            current_user = None
        if not current_user or current_user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Only admin can create SPOC/Admin users")
    if db["user"].find_one({"email": body.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    uid = db["user"].insert_one({
        "name": body.name,
        "email": str(body.email).lower(),
        "password_hash": _hash_password(body.password),
        "role": requested_role if requested_role in ("student", "spoc", "admin") else "student",
        "is_active": True,
        "created_at": _now(),
        "updated_at": _now(),
    }).inserted_id
    return {"id": str(uid), "email": body.email}


@app.post("/auth/login")
def login(body: LoginBody):
    user = db["user"].find_one({"email": str(body.email).lower()})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("password_hash") != _hash_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account disabled")
    token = secrets.token_urlsafe(32)
    expires = (_now() + timedelta(days=7)).isoformat()
    db["session"].insert_one({
        "user_id": user["_id"],
        "token": token,
        "user_agent": None,
        "ip": None,
        "created_at": _now(),
        "updated_at": _now(),
        "expires_at": expires,
    })
    u = _oid(user)
    return {"token": token, "user": {"id": u.get("id"), "name": u.get("name"), "email": u.get("email"), "role": u.get("role")}}


@app.get("/auth/me")
def me(current=Depends(get_current_user)):
    return {"user": {k: current[k] for k in ("id", "name", "email", "role") if k in current}}


# Posts
@app.get("/posts")
def list_posts():
    posts = [
        _oid(p) for p in db["post"].find({}).sort("created_at", -1)
    ]
    return {"items": posts}


@app.post("/posts")
def create_post(body: PostBody, current=Depends(get_current_user)):
    # Only admin and spoc can create posts
    require_role(current, ["admin", "spoc"])
    doc = {
        "title": body.title,
        "content": body.content,
        "author_id": current.get("id"),
        "author_name": current.get("name"),
        "visibility": body.visibility,
        "tags": body.tags or [],
        "created_at": _now(),
        "updated_at": _now(),
    }
    pid = db["post"].insert_one(doc).inserted_id
    return {"id": str(pid)}


@app.delete("/posts/{post_id}")
def delete_post(post_id: str, current=Depends(get_current_user)):
    require_role(current, ["admin", "spoc"])
    from bson import ObjectId
    try:
        res = db["post"].delete_one({"_id": ObjectId(post_id)})
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid post id")
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Post not found")
    return {"status": "deleted"}


# Resources
@app.get("/resources")
def list_resources():
    items = [_oid(x) for x in db["resource"].find({}).sort("created_at", -1)]
    return {"items": items}


@app.post("/resources")
def create_resource(body: ResourceBody, current=Depends(get_current_user)):
    # spoc or admin can create
    require_role(current, ["admin", "spoc"])
    doc = {
        "title": body.title,
        "description": body.description,
        "url": body.url,
        "file_url": body.file_url,
        "created_by": current.get("id"),
        "created_by_name": current.get("name"),
        "category": body.category,
        "tags": body.tags or [],
        "created_at": _now(),
        "updated_at": _now(),
    }
    rid = db["resource"].insert_one(doc).inserted_id
    return {"id": str(rid)}


# Notifications
@app.get("/notifications")
def get_notifications(authorization: Optional[str] = Header(None)):
    # Show broadcast and user-specific when logged in, otherwise only broadcast
    user_id = None
    try:
        if authorization and authorization.lower().startswith("bearer "):
            current = get_current_user.__wrapped__(authorization)  # type: ignore
            user_id = current.get("id") if current else None
    except Exception:
        user_id = None
    filt: Dict[str, Any] = {"$or": [{"user_id": None}]}
    if user_id:
        filt["$or"].append({"user_id": user_id})
    items = [_oid(x) for x in db["notification"].find(filt).sort("created_at", -1)]
    return {"items": items}


@app.post("/notifications")
def create_notification(body: NotificationBody, current=Depends(get_current_user)):
    # spoc or admin can send notifications
    require_role(current, ["admin", "spoc"])
    doc = {
        "user_id": body.user_id,
        "title": body.title,
        "message": body.message,
        "type": body.type,
        "link": body.link,
        "read": False,
        "created_at": _now(),
        "updated_at": _now(),
        "sender_id": current.get("id"),
        "sender_name": current.get("name"),
    }
    nid = db["notification"].insert_one(doc).inserted_id
    return {"id": str(nid)}


@app.patch("/notifications/{notification_id}/read")
def mark_notification_read(notification_id: str, current=Depends(get_current_user)):
    from bson import ObjectId
    try:
        _id = ObjectId(notification_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")
    notif = db["notification"].find_one({"_id": _id})
    if not notif:
        raise HTTPException(status_code=404, detail="Not found")
    # Only the intended user can mark as read, broadcasts can be marked by anyone
    if notif.get("user_id") and notif.get("user_id") != current.get("id") and current.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Cannot modify this notification")
    db["notification"].update_one({"_id": _id}, {"$set": {"read": True, "updated_at": _now()}})
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
