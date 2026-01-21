import os
from datetime import datetime, timedelta
from typing import Optional, List
from uuid import UUID

from fastapi import FastAPI, Depends, HTTPException, status, Body, Path, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import (
    Column,
    String,
    Boolean,
    TIMESTAMP,
    text,
    create_engine,
    ForeignKey,
    Text,
    JSON,
    Date,
    Integer,
    desc,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# App metadata with tags
openapi_tags = [
    {"name": "health", "description": "Health check"},
    {"name": "auth", "description": "Authentication endpoints"},
    {"name": "profile", "description": "Profile management"},
    {"name": "posts", "description": "Posts and engagements"},
    {"name": "analytics", "description": "Analytics metrics"},
]

app = FastAPI(
    title="Social Media Backend",
    description="Backend for authentication, profile, posts, engagements, and analytics.",
    version="1.0.0",
    openapi_tags=openapi_tags,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database configuration
def _build_db_url() -> str:
    """Build database URL from env according to social_media_database/.env.example"""
    url = os.getenv("POSTGRES_URL")
    if url:
        return url
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5000")
    user = os.getenv("POSTGRES_USER", "appuser")
    password = os.getenv("POSTGRES_PASSWORD", "dbuser123")
    db = os.getenv("POSTGRES_DB", "myapp")
    return f"postgresql+psycopg://{user}:{password}@{host}:{port}/{db}"

DATABASE_URL = _build_db_url()

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

# Security / JWT
SECRET_KEY = os.getenv("JWT_SECRET", "CHANGE_ME_IN_ENV")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# SQLAlchemy models to align with database schema created by sql_init.sh

class User(Base):
    __tablename__ = "users"
    id = Column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(Text, nullable=False)
    is_active = Column(Boolean, nullable=False, server_default=text("TRUE"))
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    profile = relationship("Profile", back_populates="user", uselist=False)
    posts = relationship("Post", back_populates="user")


class Profile(Base):
    __tablename__ = "profiles"
    id = Column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    user_id = Column(PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    display_name = Column(Text, nullable=False)
    bio = Column(Text)
    avatar_url = Column(Text)
    location = Column(Text)
    website = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    user = relationship("User", back_populates="profile")


class Post(Base):
    __tablename__ = "posts"
    id = Column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    user_id = Column(PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    media_url = Column(Text)
    visibility = Column(Text, nullable=False, server_default=text("'public'"))
    posted_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    user = relationship("User", back_populates="posts")
    engagements = relationship("Engagement", back_populates="post")


class Engagement(Base):
    __tablename__ = "engagements"
    id = Column(PGUUID(as_uuid=True), primary_key=True, server_default=text("gen_random_uuid()"))
    post_id = Column(PGUUID(as_uuid=True), ForeignKey("posts.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    type = Column(Text, nullable=False)  # like, comment, share, view
    metadata = Column(JSON, server_default=text("'{}'::jsonb"))
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))
    post = relationship("Post", back_populates="engagements")


class AnalyticsDaily(Base):
    __tablename__ = "analytics_daily"
    id = Column(Integer, primary_key=True, autoincrement=True)
    metric_date = Column(Date, nullable=False)
    user_id = Column(PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    posts_count = Column(Integer, nullable=False, server_default=text("0"))
    likes_count = Column(Integer, nullable=False, server_default=text("0"))
    comments_count = Column(Integer, nullable=False, server_default=text("0"))
    shares_count = Column(Integer, nullable=False, server_default=text("0"))
    views_count = Column(Integer, nullable=False, server_default=text("0"))
    followers_count = Column(Integer, nullable=False, server_default=text("0"))
    following_count = Column(Integer, nullable=False, server_default=text("0"))
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text("NOW()"))

# Pydantic Schemas

class Token(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(..., description="Token type, always 'bearer'")

class TokenData(BaseModel):
    user_id: Optional[UUID] = None
    email: Optional[EmailStr] = None

class RegisterRequest(BaseModel):
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="Password")

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ProfileOut(BaseModel):
    id: UUID
    user_id: UUID
    display_name: str
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None

    class Config:
        from_attributes = True

class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    location: Optional[str] = None
    website: Optional[str] = None

class PostCreate(BaseModel):
    content: str
    media_url: Optional[str] = None
    visibility: Optional[str] = Field(default="public")

class PostOut(BaseModel):
    id: UUID
    user_id: UUID
    content: str
    media_url: Optional[str] = None
    visibility: str
    posted_at: datetime

    class Config:
        from_attributes = True

class EngagementCreate(BaseModel):
    type: str = Field(..., description="one of like, comment, share, view")
    metadata: Optional[dict] = Field(default=None)

class AnalyticsSummary(BaseModel):
    metric_date: Optional[str] = None
    posts_count: int
    likes_count: int
    comments_count: int
    shares_count: int
    views_count: int
    followers_count: int
    following_count: int

# Utility functions

def get_db():
    """Yield DB session and ensure close."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    return db.query(User).filter(User.email == email).first()

def get_user(db: Session, user_id: UUID) -> Optional[User]:
    return db.query(User).filter(User.id == user_id).first()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """Decode JWT and load current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        uid: str = payload.get("sub")
        if uid is None:
            raise credentials_exception
        token_data = TokenData(user_id=UUID(uid))
    except JWTError:
        raise credentials_exception
    user = get_user(db, token_data.user_id) if token_data.user_id else None
    if user is None:
        raise credentials_exception
    return user

# Routes

# PUBLIC_INTERFACE
@app.get("/", tags=["health"], summary="Health Check")
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# PUBLIC_INTERFACE
@app.post("/auth/register", response_model=Token, tags=["auth"], summary="Register a new user")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """Register a user and return JWT.

    Parameters:
    - payload: RegisterRequest containing email and password

    Returns:
    - Token: JWT bearer token for subsequent authenticated requests
    """
    existing = get_user_by_email(db, payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(email=str(payload.email), password_hash=get_password_hash(payload.password))
    db.add(user)
    db.flush()
    # Create default profile
    profile = Profile(
        user_id=user.id, display_name=payload.email.split("@")[0], bio=None, avatar_url=None
    )
    db.add(profile)
    db.commit()
    access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
    return Token(access_token=access_token, token_type="bearer")

# PUBLIC_INTERFACE
@app.post("/auth/login", response_model=Token, tags=["auth"], summary="Login and get JWT")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login endpoint using OAuth2PasswordRequestForm."""
    user = get_user_by_email(db, form_data.username)
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
    return Token(access_token=access_token, token_type="bearer")

# PUBLIC_INTERFACE
@app.get("/profile/me", response_model=ProfileOut, tags=["profile"], summary="Get my profile")
def get_my_profile(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Return the current user's profile."""
    prof = db.query(Profile).filter(Profile.user_id == current_user.id).first()
    if not prof:
        raise HTTPException(status_code=404, detail="Profile not found")
    return prof

# PUBLIC_INTERFACE
@app.put("/profile/me", response_model=ProfileOut, tags=["profile"], summary="Update my profile")
def update_my_profile(
    payload: ProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update fields in the current user's profile."""
    prof = db.query(Profile).filter(Profile.user_id == current_user.id).first()
    if not prof:
        # create if missing
        prof = Profile(user_id=current_user.id, display_name="New User")
        db.add(prof)
        db.flush()
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(prof, field, value)
    db.commit()
    db.refresh(prof)
    return prof

# PUBLIC_INTERFACE
@app.post("/posts", response_model=PostOut, tags=["posts"], summary="Create a post")
def create_post(
    payload: PostCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a post for the current user."""
    post = Post(
        user_id=current_user.id,
        content=payload.content,
        media_url=payload.media_url,
        visibility=payload.visibility or "public",
    )
    db.add(post)
    db.commit()
    db.refresh(post)
    return post

# PUBLIC_INTERFACE
@app.get("/posts", response_model=List[PostOut], tags=["posts"], summary="List my posts")
def list_my_posts(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List posts created by current user, latest first."""
    posts = (
        db.query(Post)
        .filter(Post.user_id == current_user.id)
        .order_by(desc(Post.posted_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return posts

# PUBLIC_INTERFACE
@app.post(
    "/posts/{post_id}/engagements",
    tags=["posts"],
    summary="Create an engagement on a post",
    status_code=201,
)
def create_engagement(
    post_id: UUID = Path(..., description="Post ID"),
    payload: EngagementCreate = Body(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create an engagement (like, comment, share, view) for a post."""
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post not found")
    if payload.type not in ("like", "comment", "share", "view"):
        raise HTTPException(status_code=400, detail="Invalid engagement type")
    engagement = Engagement(
        post_id=post.id,
        user_id=current_user.id,
        type=payload.type,
        metadata=payload.metadata or {},
    )
    db.add(engagement)
    db.commit()
    return {"status": "ok"}

# PUBLIC_INTERFACE
@app.get("/analytics/summary", response_model=AnalyticsSummary, tags=["analytics"], summary="My analytics summary")
def analytics_summary(
    days: int = Query(7, ge=1, le=90, description="How many recent days to aggregate"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Aggregate analytics_daily for current user over the last N days."""
    since = datetime.utcnow().date() - timedelta(days=days - 1)
    row = (
        db.query(
            func.coalesce(func.sum(AnalyticsDaily.posts_count), 0),
            func.coalesce(func.sum(AnalyticsDaily.likes_count), 0),
            func.coalesce(func.sum(AnalyticsDaily.comments_count), 0),
            func.coalesce(func.sum(AnalyticsDaily.shares_count), 0),
            func.coalesce(func.sum(AnalyticsDaily.views_count), 0),
            func.coalesce(func.max(AnalyticsDaily.followers_count), 0),
            func.coalesce(func.max(AnalyticsDaily.following_count), 0),
        )
        .filter(AnalyticsDaily.user_id == current_user.id)
        .filter(AnalyticsDaily.metric_date >= since)
        .one()
    )
    return AnalyticsSummary(
        posts_count=row[0],
        likes_count=row[1],
        comments_count=row[2],
        shares_count=row[3],
        views_count=row[4],
        followers_count=row[5],
        following_count=row[6],
    )

# PUBLIC_INTERFACE
@app.get("/analytics/daily", tags=["analytics"], summary="Daily analytics time series")
def analytics_daily(
    days: int = Query(7, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the last N days of analytics_daily rows for the current user."""
    since = datetime.utcnow().date() - timedelta(days=days - 1)
    rows = (
        db.query(AnalyticsDaily)
        .filter(AnalyticsDaily.user_id == current_user.id)
        .filter(AnalyticsDaily.metric_date >= since)
        .order_by(AnalyticsDaily.metric_date.asc())
        .all()
    )
    return [
        AnalyticsSummary(
            metric_date=r.metric_date.isoformat(),
            posts_count=r.posts_count,
            likes_count=r.likes_count,
            comments_count=r.comments_count,
            shares_count=r.shares_count,
            views_count=r.views_count,
            followers_count=r.followers_count,
            following_count=r.following_count,
        ).model_dump()
        for r in rows
    ]
