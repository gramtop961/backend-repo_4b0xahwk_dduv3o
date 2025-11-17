"""
Database Schemas for Club Management App

Each Pydantic model represents a MongoDB collection.
The collection name is the lowercase class name.

Collections:
- User (roles: admin, spoc, student)
- Session (login sessions)
- Post (announcements, club posts)
- Resource (training/learning materials)
- Notification (user-facing notifications)
"""
from typing import Optional, List, Literal
from pydantic import BaseModel, Field, EmailStr


class User(BaseModel):
    """
    Users collection schema
    Roles:
    - admin: Full control
    - spoc: Club SPOC/moderator access
    - student: Regular student
    """
    name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    password_hash: str = Field(..., description="SHA256 password hash")
    role: Literal["admin", "spoc", "student"] = Field("student")
    avatar_url: Optional[str] = None
    is_active: bool = True


class Session(BaseModel):
    """Login sessions bound to a user"""
    user_id: str
    token: str
    user_agent: Optional[str] = None
    ip: Optional[str] = None
    expires_at: Optional[str] = None  # ISO datetime string


class Post(BaseModel):
    """Club posts/announcements"""
    title: str = Field(..., min_length=3, max_length=200)
    content: str = Field(..., min_length=1)
    author_id: str
    author_name: str
    visibility: Literal["public", "members"] = "public"
    tags: List[str] = []


class Resource(BaseModel):
    """Training/learning resources"""
    title: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = None
    url: Optional[str] = None
    file_url: Optional[str] = None
    created_by: str
    created_by_name: str
    category: Optional[str] = None
    tags: List[str] = []


class Notification(BaseModel):
    """User notifications"""
    user_id: Optional[str] = None  # if None => broadcast
    title: str
    message: str
    type: Literal["info", "success", "warning", "error"] = "info"
    read: bool = False
    link: Optional[str] = None
