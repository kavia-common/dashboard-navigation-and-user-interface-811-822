import os
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Body, Path, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

# Configuration helpers
def _get_db_url_from_env() -> str:
    """Build a PostgreSQL SQLAlchemy URL from POSTGRES_* envs or POSTGRES_URL."""
    # PUBLIC_INTERFACE
    url = os.getenv("POSTGRES_URL", "").strip()
    if url:
        return url
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5000")
    user = os.getenv("POSTGRES_USER", "appuser")
    password = os.getenv("POSTGRES_PASSWORD", "dbuser123")
    db = os.getenv("POSTGRES_DB", "myapp")
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{db}"

def _get_cors_origins() -> List[str]:
    raw = os.getenv("CORS_ALLOW_ORIGINS", "*")
    if not raw:
        return ["*"]
    items = [o.strip() for o in raw.split(",") if o.strip()]
    return items if items else ["*"]

JWT_SECRET = os.getenv("JWT_SECRET", "change_me")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Create database engine
DATABASE_URL = _get_db_url_from_env()
engine: Engine = create_engine(DATABASE_URL, pool_pre_ping=True)

# Pydantic Schemas
class Token(BaseModel):
    access_token: str = Field(..., description="JWT token")
    token_type: str = Field(..., description="Token type e.g., bearer")

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

class ProfileOut(BaseModel):
    id: str
    user_id: str
    display_name: str
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None

class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None

class PostCreate(BaseModel):
    content: str
    media_url: Optional[str] = None
    visibility: Optional[str] = "public"

class PostOut(BaseModel):
    id: str
    user_id: str
    content: str
    media_url: Optional[str] = None
    visibility: str
    posted_at: datetime

class EngagementCreate(BaseModel):
    type: str
    metadata: Optional[dict] = None

class AnalyticsSummary(BaseModel):
    metric_date: Optional[str] = None
    posts_count: int
    likes_count: int
    comments_count: int
    shares_count: int
    views_count: int
    followers_count: int
    following_count: int

# Utility auth/db helpers
def _hash_password(password: str) -> str:
    return pwd_context.hash(password)

def _verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def _create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode = {"sub": subject, "exp": expire}
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def _get_user_by_email(email: str) -> Optional[dict]:
    with engine.connect() as conn:
        res = conn.execute(text("SELECT id, email, password_hash, role, is_active FROM users WHERE email = :email"), {"email": email}).mappings().first()
        return dict(res) if res else None

def _get_user_by_id(user_id: str) -> Optional[dict]:
    with engine.connect() as conn:
        res = conn.execute(text("SELECT id, email, role, is_active FROM users WHERE id = :id"), {"id": user_id}).mappings().first()
        return dict(res) if res else None

def _create_user(email: str, password: str) -> dict:
    with engine.begin() as conn:
        res = conn.execute(
            text("INSERT INTO users (email, password_hash, role, is_active) VALUES (:email, :hash, 'user', 1) RETURNING id, email, role, is_active"),
            {"email": email, "hash": _hash_password(password)}
        )
        row = res.mappings().first()
        # also create a profile with default display_name
        conn.execute(
            text("INSERT INTO profiles (user_id, display_name) VALUES (:uid, :dn)"),
            {"uid": row["id"], "dn": email.split("@")[0]}
        )
        return dict(row)

def _get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = _get_user_by_id(user_id)
    if not user or not user.get("is_active"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive or missing user")
    return user

# FastAPI app
app = FastAPI(
    title="Social Media Backend",
    description="Backend for authentication, profile, posts, engagements, and analytics.",
    version="1.0.0",
    openapi_tags=[
        {"name": "health", "description": "Health check"},
        {"name": "auth", "description": "Authentication"},
        {"name": "profile", "description": "Profile operations"},
        {"name": "posts", "description": "Posts and engagements"},
        {"name": "analytics", "description": "Analytics endpoints"},
    ],
)

# Configure CORS
origins = _get_cors_origins()
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
@app.get("/", tags=["health"], summary="Health Check")
def health_check():
    """Health check endpoint to verify the service is running."""
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

@app.post("/auth/register", response_model=Token, tags=["auth"], summary="Register a new user")
def register(payload: RegisterRequest):
    """Register a new user and return a JWT token."""
    existing = _get_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = _create_user(payload.email, payload.password)
    access_token = _create_access_token(user["id"])
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/login", response_model=Token, tags=["auth"], summary="Login and get JWT")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login with username/password (username is email).
    Returns a JWT bearer token if credentials are valid.
    """
    user = _get_user_by_email(form_data.username)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    # fetch hash
    with engine.connect() as conn:
        row = conn.execute(text("SELECT password_hash FROM users WHERE id = :id"), {"id": user["id"]}).mappings().first()
        if not row or not _verify_password(form_data.password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = _create_access_token(user["id"])
    return {"access_token": token, "token_type": "bearer"}

@app.get("/profile/me", response_model=ProfileOut, tags=["profile"], summary="Get my profile")
def get_my_profile(current=Depends(_get_current_user)):
    """Return the current user's profile."""
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id, user_id, display_name, bio, avatar_url, location, website FROM profiles WHERE user_id = :uid"),
            {"uid": current["id"]}
        ).mappings().first()
        if not row:
            raise HTTPException(status_code=404, detail="Profile not found")
        return dict(row)

@app.put("/profile/me", response_model=ProfileOut, tags=["profile"], summary="Update my profile")
def update_my_profile(payload: ProfileUpdate, current=Depends(_get_current_user)):
    """Update the current user's profile."""
    updates = {
        "display_name": payload.display_name,
        "bio": payload.bio,
        "avatar_url": payload.avatar_url,
        "location": payload.location,
        "website": payload.website,
    }
    # Build dynamic SET clause for provided fields
    set_parts = []
    params = {"uid": current["id"]}
    for k, v in updates.items():
        if v is not None:
            set_parts.append(f"{k} = :{k}")
            params[k] = v
    if set_parts:
        with engine.begin() as conn:
            conn.execute(text(f"UPDATE profiles SET {', '.join(set_parts)} WHERE user_id = :uid"), params)

    return get_my_profile(current=current)

@app.get("/posts", response_model=List[PostOut], tags=["posts"], summary="List my posts")
def list_my_posts(limit: int = Query(default=20), offset: int = Query(default=0), current=Depends(_get_current_user)):
    """List posts for the current user with pagination."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT id, user_id, content, media_url, visibility, posted_at "
                "FROM posts WHERE user_id = :uid ORDER BY posted_at DESC LIMIT :limit OFFSET :offset"
            ),
            {"uid": current["id"], "limit": limit, "offset": offset}
        ).mappings().all()
        return [dict(r) for r in rows]

@app.post("/posts", response_model=PostOut, tags=["posts"], summary="Create a post")
def create_post(payload: PostCreate = Body(...), current=Depends(_get_current_user)):
    """Create a new post."""
    with engine.begin() as conn:
        res = conn.execute(
            text(
                "INSERT INTO posts (user_id, content, media_url, visibility, posted_at) "
                "VALUES (:uid, :content, :media_url, :visibility, NOW()) "
                "RETURNING id, user_id, content, media_url, visibility, posted_at"
            ),
            {
                "uid": current["id"],
                "content": payload.content,
                "media_url": payload.media_url,
                "visibility": payload.visibility or "public",
            }
        )
        row = res.mappings().first()
        return dict(row)

@app.post("/posts/{post_id}/engagements", status_code=201, tags=["posts"], summary="Create an engagement on a post")
def create_engagement(
    post_id: str = Path(..., description="Post ID (UUID)"),
    payload: EngagementCreate = Body(...),
    current=Depends(_get_current_user),
):
    """Create an engagement on a post (like, comment, etc.)."""
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO engagements (post_id, user_id, type, metadata, engaged_at) "
                "VALUES (:pid, :uid, :type, :metadata, NOW())"
            ),
            {
                "pid": post_id,
                "uid": current["id"],
                "type": payload.type,
                "metadata": payload.metadata or {},
            }
        )
    return {"status": "created"}

@app.get("/analytics/summary", response_model=AnalyticsSummary, tags=["analytics"], summary="My analytics summary")
def my_analytics_summary(days: Optional[int] = Query(default=30), current=Depends(_get_current_user)):
    """Return aggregated analytics summary for the current user."""
    with engine.connect() as conn:
        # Simplified aggregation using analytics_daily table
        res = conn.execute(
            text(
                "SELECT "
                "COALESCE(SUM(posts_count),0) AS posts_count, "
                "COALESCE(SUM(likes_count),0) AS likes_count, "
                "COALESCE(SUM(comments_count),0) AS comments_count, "
                "COALESCE(SUM(shares_count),0) AS shares_count, "
                "COALESCE(SUM(views_count),0) AS views_count, "
                "COALESCE(MAX(followers_count),0) AS followers_count, "
                "COALESCE(MAX(following_count),0) AS following_count "
                "FROM analytics_daily WHERE user_id = :uid AND metric_date >= CURRENT_DATE - (:days || ' days')::interval"
            ),
            {"uid": current["id"], "days": days or 30}
        ).mappings().first()
        data = dict(res) if res else {}
    return AnalyticsSummary(**{
        "metric_date": None,
        "posts_count": data.get("posts_count", 0),
        "likes_count": data.get("likes_count", 0),
        "comments_count": data.get("comments_count", 0),
        "shares_count": data.get("shares_count", 0),
        "views_count": data.get("views_count", 0),
        "followers_count": data.get("followers_count", 0),
        "following_count": data.get("following_count", 0),
    })
