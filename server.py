from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import List, Optional, Literal
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import asyncio

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Config
MONGO_URL = os.environ['MONGO_URL']
DB_NAME = os.environ['DB_NAME']
SMTP_HOST = os.environ['SMTP_HOST']
SMTP_PORT = int(os.environ['SMTP_PORT'])
SMTP_USER = os.environ['SMTP_USER']
SMTP_PASSWORD = os.environ['SMTP_PASSWORD'].replace(' ', '')  # Gmail App Password sem espaços
EMAIL_SENDER_NAME = os.environ['EMAIL_SENDER_NAME']
DEFAULT_RECIPIENT = os.environ['DEFAULT_RECIPIENT']
JWT_SECRET = os.environ['JWT_SECRET']
JWT_ALGORITHM = os.environ['JWT_ALGORITHM']
JWT_EXPIRATION_HOURS = int(os.environ.get('JWT_EXPIRATION_HOURS', '168'))
ADMIN_USERNAME = os.environ['ADMIN_USERNAME']
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']
ALLOWED_DOMAIN = os.environ['ALLOWED_DOMAIN']

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

app = FastAPI(title="Escola Secundária de Latino Coelho - Reporte de Anomalias")
api_router = APIRouter(prefix="/api")
security = HTTPBearer()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ---------- Models ----------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def must_be_institutional(cls, v: str) -> str:
        if not v.lower().endswith(f"@{ALLOWED_DOMAIN}"):
            raise ValueError(f"O email deve ser do domínio @{ALLOWED_DOMAIN}")
        return v.lower()

    @field_validator("password")
    @classmethod
    def password_min_len(cls, v: str) -> str:
        if len(v) < 6:
            raise ValueError("A palavra-passe deve ter pelo menos 6 caracteres")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def email_lower(cls, v: str) -> str:
        return v.lower()


class AdminLoginRequest(BaseModel):
    username: str
    password: str


class UserTypeRequest(BaseModel):
    user_type: Literal["aluno", "professor"]


class ReportCreate(BaseModel):
    nome: str
    tipo: Literal["aluno", "professor"]
    local: str
    sala: Optional[str] = None
    descricao: str
    info_adicional: Optional[str] = None

    @field_validator("nome", "local", "descricao")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Campo obrigatório")
        return v.strip()


class RecipientCreate(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def email_lower(cls, v: str) -> str:
        return v.lower()


# ---------- Helpers ----------
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def create_token(payload: dict) -> str:
    data = payload.copy()
    data["exp"] = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    return jwt.encode(data, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Sessão expirada")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = decode_token(credentials.credentials)
    if payload.get("role") != "user":
        raise HTTPException(status_code=403, detail="Acesso negado")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Utilizador não encontrado")
    return user


async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = decode_token(credentials.credentials)
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acesso negado - apenas administradores")
    return {"username": payload["sub"], "role": "admin"}


def send_email_via_smtp(subject: str, html_body: str, recipients: List[str]) -> dict:
    """Synchronous Gmail SMTP send (runs in thread executor)."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = formataddr((EMAIL_SENDER_NAME, SMTP_USER))
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, recipients, msg.as_string())

        logger.info(f"Email enviado via Gmail SMTP para {recipients}")
        return {"success": True}
    except smtplib.SMTPAuthenticationError as exc:
        logger.exception("Falha de autenticação SMTP Gmail")
        return {"success": False, "error": f"Autenticação SMTP falhou: {exc}"}
    except Exception as exc:
        logger.exception(f"Falha ao enviar email via Gmail SMTP: {exc}")
        return {"success": False, "error": str(exc)}


def build_report_email_html(report: dict, user_email: str, user_type: str) -> str:
    sala = report.get("sala") or "—"
    info = report.get("info_adicional") or "—"
    nome = report.get("nome") or "—"
    tipo = (report.get("tipo") or user_type or "").capitalize() or "—"
    ts = report.get("created_at", datetime.now(timezone.utc).isoformat())
    return f"""
    <!doctype html>
    <html><head><meta charset="utf-8"></head>
    <body style="font-family: Arial, Helvetica, sans-serif; background-color:#f9fafb; padding:24px; color:#111827;">
      <table width="100%" cellpadding="0" cellspacing="0" style="max-width:600px; margin:0 auto; background-color:#ffffff; border-radius:12px; overflow:hidden; border:1px solid #E5E7EB;">
        <tr><td style="padding:20px 24px; background-color:#166534; color:#ffffff;">
          <h1 style="margin:0; font-size:18px;">Novo Relato de Anomalia</h1>
          <p style="margin:4px 0 0; font-size:12px; opacity:0.85;">Escola Secundária de Latino Coelho</p>
        </td></tr>
        <tr><td style="padding:24px;">
          <p style="margin:0 0 8px; font-size:14px;"><strong>Nome:</strong> {nome}</p>
          <p style="margin:0 0 8px; font-size:14px;"><strong>Perfil:</strong> {tipo}</p>
          <p style="margin:0 0 16px; font-size:13px; color:#6B7280;"><strong>Conta:</strong> {user_email}</p>
          <p style="margin:0 0 16px; font-size:12px; color:#6B7280;"><strong>Data:</strong> {ts}</p>
          <hr style="border:none; border-top:1px solid #E5E7EB; margin:16px 0;" />
          <p style="margin:0 0 8px;"><strong>Local da Anomalia:</strong><br/>{report.get('local','')}</p>
          <p style="margin:12px 0 8px;"><strong>Número da Sala:</strong><br/>{sala}</p>
          <p style="margin:12px 0 8px;"><strong>Descrição do Problema:</strong><br/>{report.get('descricao','')}</p>
          <p style="margin:12px 0 8px;"><strong>Informações Adicionais:</strong><br/>{info}</p>
        </td></tr>
        <tr><td style="padding:16px 24px; background-color:#F9FAFB; color:#6B7280; font-size:11px;">
          Esta mensagem foi gerada automaticamente pela aplicação de relato de anomalias do Agrupamento de Escolas Latino Coelho - Lamego.
        </td></tr>
      </table>
    </body></html>
    """


# ---------- Routes ----------
@api_router.get("/")
async def root():
    return {"message": "Escola Secundária de Latino Coelho - Reporte de Anomalias API", "domain": ALLOWED_DOMAIN}


@api_router.post("/auth/register")
async def register(payload: RegisterRequest):
    existing = await db.users.find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Este email já está registado")
    user_id = str(uuid.uuid4())
    user_doc = {
        "id": user_id,
        "email": payload.email,
        "password": hash_password(payload.password),
        "user_type": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.users.insert_one(user_doc)
    token = create_token({"sub": user_id, "role": "user", "email": payload.email})
    return {
        "token": token,
        "user": {"id": user_id, "email": payload.email, "user_type": None},
    }


@api_router.post("/auth/login")
async def login(payload: LoginRequest):
    user = await db.users.find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user["password"]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    if not payload.email.endswith(f"@{ALLOWED_DOMAIN}"):
        raise HTTPException(status_code=403, detail=f"Apenas emails @{ALLOWED_DOMAIN}")
    token = create_token({"sub": user["id"], "role": "user", "email": user["email"]})
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "user_type": user.get("user_type"),
        },
    }


@api_router.post("/auth/admin-login")
async def admin_login(payload: AdminLoginRequest):
    if payload.username != ADMIN_USERNAME or payload.password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Credenciais de administrador inválidas")
    token = create_token({"sub": ADMIN_USERNAME, "role": "admin"})
    return {"token": token, "admin": {"username": ADMIN_USERNAME}}


@api_router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return {"user": user}


@api_router.post("/user/type")
async def set_user_type(payload: UserTypeRequest, user: dict = Depends(get_current_user)):
    await db.users.update_one(
        {"id": user["id"]},
        {"$set": {"user_type": payload.user_type}},
    )
    return {"user_type": payload.user_type}


@api_router.post("/reports")
async def create_report(payload: ReportCreate, user: dict = Depends(get_current_user)):
    if not user.get("user_type"):
        raise HTTPException(status_code=400, detail="Selecione o seu perfil (Aluno ou Professor) primeiro")

    report_id = str(uuid.uuid4())
    now_iso = datetime.now(timezone.utc).isoformat()
    report_doc = {
        "id": report_id,
        "user_id": user["id"],
        "user_email": user["email"],
        "user_type": user["user_type"],
        "nome": payload.nome,
        "tipo": payload.tipo,
        "local": payload.local,
        "sala": payload.sala,
        "descricao": payload.descricao,
        "info_adicional": payload.info_adicional,
        "created_at": now_iso,
        "email_sent": False,
        "email_error": None,
    }
    await db.reports.insert_one(report_doc.copy())

    # Get recipients
    recipients_cursor = db.recipients.find({"active": True}, {"_id": 0, "email": 1})
    recipients = [r["email"] async for r in recipients_cursor]

    email_status = {"success": False, "error": "Sem destinatários configurados"}
    if recipients:
        html_body = build_report_email_html(report_doc, user["email"], user["user_type"])
        subject = f"[Latino Coelho] Anomalia em {payload.local}"
        loop = asyncio.get_event_loop()
        email_status = await loop.run_in_executor(
            None, send_email_via_smtp, subject, html_body, recipients
        )

    await db.reports.update_one(
        {"id": report_id},
        {"$set": {
            "email_sent": email_status.get("success", False),
            "email_error": None if email_status.get("success") else email_status.get("error"),
        }},
    )

    report_doc["email_sent"] = email_status.get("success", False)
    report_doc["email_error"] = None if email_status.get("success") else email_status.get("error")
    report_doc.pop("_id", None)
    return {"report": report_doc, "email_sent": email_status.get("success", False)}


@api_router.get("/reports/mine")
async def list_my_reports(user: dict = Depends(get_current_user)):
    cursor = db.reports.find({"user_id": user["id"]}, {"_id": 0}).sort("created_at", -1)
    reports = [r async for r in cursor]
    return {"reports": reports}


@api_router.get("/admin/reports")
async def list_all_reports(_: dict = Depends(get_current_admin)):
    cursor = db.reports.find({}, {"_id": 0}).sort("created_at", -1)
    reports = [r async for r in cursor]
    return {"reports": reports}


@api_router.get("/admin/recipients")
async def list_recipients(_: dict = Depends(get_current_admin)):
    cursor = db.recipients.find({}, {"_id": 0})
    items = [r async for r in cursor]
    return {"recipients": items}


@api_router.post("/admin/recipients")
async def add_recipient(payload: RecipientCreate, _: dict = Depends(get_current_admin)):
    existing = await db.recipients.find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Este email já está na lista")
    rid = str(uuid.uuid4())
    doc = {
        "id": rid,
        "email": payload.email,
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.recipients.insert_one(doc.copy())
    doc.pop("_id", None)
    return {"recipient": doc}


@api_router.delete("/admin/recipients/{recipient_id}")
async def delete_recipient(recipient_id: str, _: dict = Depends(get_current_admin)):
    result = await db.recipients.delete_one({"id": recipient_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Destinatário não encontrado")
    return {"deleted": True}


@api_router.patch("/admin/recipients/{recipient_id}/toggle")
async def toggle_recipient(recipient_id: str, _: dict = Depends(get_current_admin)):
    doc = await db.recipients.find_one({"id": recipient_id})
    if not doc:
        raise HTTPException(status_code=404, detail="Destinatário não encontrado")
    new_active = not doc.get("active", True)
    await db.recipients.update_one({"id": recipient_id}, {"$set": {"active": new_active}})
    return {"id": recipient_id, "active": new_active}


# ---------- Startup ----------
@app.on_event("startup")
async def startup():
    # Seed default recipient if not exists
    existing = await db.recipients.find_one({"email": DEFAULT_RECIPIENT.lower()})
    if not existing:
        await db.recipients.insert_one({
            "id": str(uuid.uuid4()),
            "email": DEFAULT_RECIPIENT.lower(),
            "active": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        logger.info(f"Default recipient seeded: {DEFAULT_RECIPIENT}")
    logger.info(f"App started. SMTP: {SMTP_USER}, Allowed domain: @{ALLOWED_DOMAIN}, Admin user: {ADMIN_USERNAME}")


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
