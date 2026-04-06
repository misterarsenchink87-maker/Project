from __future__ import annotations

import base64
import hashlib
import hmac
import os
from enum import Enum
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from sqlalchemy import Enum as SAEnum, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

SECRET_KEY = "KTZ_SECRET_KEY_2024"
ALGORITHM = "HS256"
DATABASE_URL = "sqlite:///./ktz.db"

PBKDF2_ALG = "sha256"
PBKDF2_ITERATIONS = 210_000
PBKDF2_SALT_BYTES = 16

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="KTZ Digital Twin API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class Role(str, Enum):
    passenger = "Пассажир"
    machinist = "Машинист"
    manager = "Руководитель"


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(SAEnum(Role))
    assigned_train: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)


class Train(Base):
    __tablename__ = "trains"

    id: Mapped[int] = mapped_column(primary_key=True)
    train_code: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    route_from: Mapped[str] = mapped_column(String(80))
    route_to: Mapped[str] = mapped_column(String(80))
    route_key: Mapped[str] = mapped_column(String(64), unique=True)
    status: Mapped[str] = mapped_column(String(32), default="В пути")


Base.metadata.create_all(bind=engine)


class UserOut(BaseModel):
    full_name: str
    email: EmailStr
    role: Role
    assigned_train: Optional[str] = None


class TrainOut(BaseModel):
    train_code: str
    route_from: str
    route_to: str
    route_key: str
    status: str


class RegisterIn(BaseModel):
    full_name: str
    email: EmailStr
    password: str


class LoginOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


PUBLIC_TRAINS = [
    ("KZ8A-001", "Астана", "Алматы", "astana-almaty", "В пути"),
    ("ТЭ33А-0142", "Алматы", "Шымкент", "almaty-shymkent", "В пути"),
    ("2ТЭ116-893", "Актобе", "Астана", "aktobe-astana", "На линии"),
    ("ТЭМ18-411", "Павлодар", "Семей", "pavlodar-semey", "В пути"),
    ("ВЛ60-778", "Шымкент", "Кызылорда", "shymkent-kyzylorda", "На линии"),
    ("KZ8A-007", "Алматы", "Атырау", "almaty-atyrau", "В пути"),
    ("ТЭ33А-0081", "Алматы", "Мангышлак", "almaty-mangyshlak", "В пути"),
    ("2ТЭ116-551", "Астана", "Костанай", "astana-kostanay", "В пути"),
    ("KZ8A-012", "Астана", "Павлодар", "astana-pavlodar", "В пути"),
]


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def seed_trains(db: Session) -> None:
    existing = {row[0] for row in db.execute(select(Train.train_code)).all()}
    changed = False
    for code, route_from, route_to, route_key, status in PUBLIC_TRAINS:
        if code in existing:
            continue
        db.add(
            Train(
                train_code=code,
                route_from=route_from,
                route_to=route_to,
                route_key=route_key,
                status=status,
            )
        )
        changed = True
    if changed:
        db.commit()


def normalize_email(email: str) -> str:
    return email.strip().lower()


def detect_role(email: str) -> Role:
    value = normalize_email(email)
    local, _, domain = value.partition("@")
    probe = f"{local} {domain} {value}"
    if any(word in probe for word in ("manager", "admin", "руковод", "supervisor", "chief")):
        return Role.manager
    if any(word in probe for word in ("machinist", "driver", "локомотив", "trainman", "машинист")):
        return Role.machinist
    return Role.passenger


def assign_train(db: Session) -> Optional[str]:
    seed_trains(db)
    taken = {
        row[0]
        for row in db.execute(select(User.assigned_train).where(User.assigned_train.is_not(None))).all()
        if row[0]
    }
    for train in db.scalars(select(Train).order_by(Train.id)).all():
        if train.train_code not in taken:
            return train.train_code
    first = db.scalar(select(Train).order_by(Train.id))
    return first.train_code if first else None


def hash_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValueError("Password must be a string")

    password_bytes = password.encode("utf-8")
    salt = os.urandom(PBKDF2_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        PBKDF2_ALG,
        password_bytes,
        salt,
        PBKDF2_ITERATIONS,
    )
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_b64 = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt_b64}${digest_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations_str, salt_b64, digest_b64 = stored_hash.split("$", 3)
    except ValueError:
        return False

    if scheme != "pbkdf2_sha256":
        return False

    try:
        iterations = int(iterations_str)
        salt = base64.urlsafe_b64decode(salt_b64 + "=" * (-len(salt_b64) % 4))
        expected = base64.urlsafe_b64decode(digest_b64 + "=" * (-len(digest_b64) % 4))
    except Exception:
        return False

    computed = hashlib.pbkdf2_hmac(
        PBKDF2_ALG,
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(computed, expected)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    email = payload.get("sub")
    if not email:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.scalar(select(User).where(User.email == email))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@app.post("/auth/register", response_model=UserOut)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    seed_trains(db)
    email = normalize_email(payload.email)
    existing = db.scalar(select(User).where(User.email == email))
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    role = detect_role(email)
    assigned_train = assign_train(db) if role == Role.machinist else None

    user = User(
        full_name=payload.full_name.strip(),
        email=email,
        password_hash=hash_password(payload.password),
        role=role,
        assigned_train=assigned_train,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=LoginOut)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = normalize_email(form_data.username)
    user = db.scalar(select(User).where(User.email == email))
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Wrong credentials")

    token = jwt.encode({"sub": user.email}, SECRET_KEY, algorithm=ALGORITHM)
    return LoginOut(access_token=token)


@app.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@app.get("/trains", response_model=list[TrainOut])
def list_trains(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    seed_trains(db)
    trains = db.scalars(select(Train).order_by(Train.id)).all()

    if user.role == Role.manager:
        return trains

    if user.role == Role.machinist:
        return [t for t in trains if t.train_code == user.assigned_train]

    return trains


@app.get("/")
def healthcheck():
    return {"status": "ok", "service": "KTZ Digital Twin API"}
