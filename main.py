from fastapi import FastAPI, Request, Form, Response, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import anthropic
import os
import json
import pg8000.native
import ssl
from urllib.parse import urlparse
from datetime import datetime, timezone
import secrets
import string
import random
import logging
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Startup validation ────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set")

DATABASE_URL   = os.environ.get("DATABASE_URL", "")
SECRET_KEY     = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")

# ── App setup ─────────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="NBFC AI Platform v2.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
templates  = Jinja2Templates(directory="templates")
client     = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
serializer = URLSafeTimedSerializer(SECRET_KEY)

# ── Loan product rules ────────────────────────────────────────────────────────
LOAN_RULES = {
    "Personal Loan": {
        "max_tenure": 60, "min_cibil": 700, "max_foir": 50,
        "typical_rate": "12-24", "max_ltv": None,
        "key_check": "Income stability and clean credit history are primary factors."
    },
    "Home Loan": {
        "max_tenure": 300, "min_cibil": 650, "max_foir": 55,
        "typical_rate": "8.5-11", "max_ltv": 80,
        "key_check": "Property valuation, LTV ratio (max 80%), and legal title clearance are critical."
    },
    "Car Loan": {
        "max_tenure": 84, "min_cibil": 680, "max_foir": 50,
        "typical_rate": "9-14", "max_ltv": 85,
        "key_check": "Vehicle valuation, ex-showroom price, insurance, and RC registration required."
    },
    "Gold Loan": {
        "max_tenure": 12, "min_cibil": 0, "max_foir": 70,
        "typical_rate": "9-18", "max_ltv": 75,
        "key_check": "Gold purity (18-22 karat), weight, and RBI LTV cap of 75% apply. No CIBIL needed."
    },
    "Business Loan": {
        "max_tenure": 60, "min_cibil": 680, "max_foir": 60,
        "typical_rate": "14-24", "max_ltv": None,
        "key_check": "GST returns, bank statements (12 months), business vintage (min 2 years) required."
    },
    "Loan Against Property": {
        "max_tenure": 180, "min_cibil": 650, "max_foir": 55,
        "typical_rate": "9.5-14", "max_ltv": 65,
        "key_check": "Property must be free of legal disputes. LTV max 65%. Rental income considered."
    },
    "Two-Wheeler Loan": {
        "max_tenure": 48, "min_cibil": 650, "max_foir": 45,
        "typical_rate": "10-18", "max_ltv": 90,
        "key_check": "Vehicle on-road price, dealer invoice, and borrower local stability matter."
    },
    "Education Loan": {
        "max_tenure": 84, "min_cibil": 600, "max_foir": 40,
        "typical_rate": "9-13", "max_ltv": None,
        "key_check": "Institution ranking, course employability, co-borrower income, and collateral for loans above Rs 7.5L."
    },
    "Microfinance / JLG Loan": {
        "max_tenure": 24, "min_cibil": 0, "max_foir": 50,
        "typical_rate": "18-24", "max_ltv": None,
        "key_check": "Group guarantee, household income verification, and no overlapping MFI loans checked."
    }
}

# ── Database ──────────────────────────────────────────────────────────────────
def get_db_conn():
    parsed = urlparse(DATABASE_URL)
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    return pg8000.native.Connection(
        host=parsed.hostname,
        database=parsed.path.lstrip("/"),
        user=parsed.username,
        password=parsed.password,
        port=parsed.port or 5432,
        ssl_context=ssl_ctx
    )

def init_db():
    try:
        conn = get_db_conn()
        conn.run("""
            CREATE TABLE IF NOT EXISTS loan_applications (
                id                   SERIAL PRIMARY KEY,
                application_id       VARCHAR(30)  UNIQUE NOT NULL,
                applicant_name       VARCHAR(100),
                age                  INTEGER,
                employment_type      VARCHAR(60),
                loan_type            VARCHAR(60),
                loan_amount          NUMERIC(15,2),
                loan_tenure          INTEGER,
                cibil_score          INTEGER,
                monthly_income       NUMERIC(15,2),
                decision             VARCHAR(20),
                risk_level           VARCHAR(10),
                risk_score           INTEGER,
                approved_amount      NUMERIC(15,2),
                interest_rate        NUMERIC(5,2),
                foir                 NUMERIC(5,1),
                ltv                  NUMERIC(5,1),
                emi_estimate         NUMERIC(15,2),
                fraud_flags          TEXT  DEFAULT '[]',
                regulatory_flags     TEXT  DEFAULT '[]',
                strengths            TEXT  DEFAULT '[]',
                concerns             TEXT  DEFAULT '[]',
                documentation_required TEXT DEFAULT '[]',
                reason               TEXT,
                recommendation       TEXT,
                created_at           TIMESTAMPTZ DEFAULT NOW()
            )
        """)
        conn.close()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.error(f"❌ DB init failed: {e}")

@app.on_event("startup")
async def startup():
    if DATABASE_URL:
        init_db()
    else:
        logger.warning("⚠️  DATABASE_URL not set — running without persistence")

# ── Utilities ─────────────────────────────────────────────────────────────────
def generate_app_id() -> str:
    today  = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"LN-{today}-{suffix}"

def verify_session(session: str | None) -> str | None:
    if not session:
        return None
    try:
        data = serializer.loads(session, max_age=86400)   # 24-hour session
        return data.get("username")
    except (BadSignature, SignatureExpired):
        return None

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username.strip() == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = serializer.dumps({"username": username.strip()})
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie("session", token, httponly=True, max_age=86400, samesite="lax")
        return resp
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": "Invalid username or password. Please try again."
    })

@app.post("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("session")
    return resp

# ── Main routes ───────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home(request: Request, session: str = Cookie(default=None)):
    username = verify_session(session)
    if not username:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "loan_types": list(LOAN_RULES.keys()),
        "username": username
    })

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, session: str = Cookie(default=None)):
    username = verify_session(session)
    if not username:
        return RedirectResponse(url="/login", status_code=303)

    stats = {"total": 0, "approved": 0, "rejected": 0, "conditional": 0, "approval_rate": 0.0}
    applications = []

    if DATABASE_URL:
        try:
            conn = get_db_conn()
            rows = conn.run("""
                SELECT application_id, applicant_name, loan_type, loan_amount,
                       decision, risk_level, risk_score, approved_amount,
                       interest_rate, foir, cibil_score, employment_type, created_at
                FROM loan_applications
                ORDER BY created_at DESC
                LIMIT 100
            """)
            for r in rows:
                applications.append({
                    "application_id":  r[0],
                    "applicant_name":  r[1],
                    "loan_type":       r[2],
                    "loan_amount":     float(r[3] or 0),
                    "decision":        r[4],
                    "risk_level":      r[5],
                    "risk_score":      r[6],
                    "approved_amount": float(r[7] or 0),
                    "interest_rate":   float(r[8] or 0),
                    "foir":            float(r[9] or 0),
                    "cibil_score":     r[10],
                    "employment_type": r[11],
                    "created_at":      r[12].strftime("%d %b %Y, %I:%M %p") if r[12] else ""
                })
            counts = conn.run("""
                SELECT COUNT(*),
                    COUNT(*) FILTER (WHERE decision = 'APPROVED'),
                    COUNT(*) FILTER (WHERE decision = 'REJECTED'),
                    COUNT(*) FILTER (WHERE decision = 'CONDITIONAL')
                FROM loan_applications
            """)
            if counts:
                t, a, r_, c = counts[0]
                t = int(t or 0)
                a = int(a or 0)
                stats = {
                    "total": t, "approved": a,
                    "rejected": int(r_ or 0), "conditional": int(c or 0),
                    "approval_rate": round((a / t * 100) if t > 0 else 0, 1)
                }
            conn.close()
        except Exception as e:
            logger.error(f"Dashboard DB error: {e}")

    return templates.TemplateResponse("dashboard.html", {
        "request":      request,
        "username":     username,
        "stats":        stats,
        "applications": applications
    })

# ── Loan analysis ─────────────────────────────────────────────────────────────
@app.post("/analyze-loan")
@limiter.limit("10/minute")
def analyze_loan(
    request:          Request,
    session:          str   = Cookie(default=None),
    full_name:        str   = Form(...),
    age:              int   = Form(...),
    monthly_income:   float = Form(...),
    loan_amount:      float = Form(...),
    loan_tenure:      int   = Form(...),
    employment_type:  str   = Form(...),
    loan_type:        str   = Form(...),
    cibil_score:      int   = Form(...),
    existing_loans:   int   = Form(...),
    loan_purpose:     str   = Form(...),
    monthly_expenses: float = Form(...),
    collateral_value: float = Form(0),
    business_vintage: int   = Form(0)
):
    if not verify_session(session):
        return JSONResponse({"error": "Session expired. Please log in again."}, status_code=401)

    # Sanitize inputs
    full_name    = full_name.strip()[:100]
    loan_purpose = loan_purpose.strip()[:200]

    if loan_type not in LOAN_RULES:
        return JSONResponse({"error": "Invalid loan type selected."}, status_code=400)

    # Pre-compute financials before sending to Claude
    rules        = LOAN_RULES[loan_type]
    rate_mid     = float(rules["typical_rate"].split("-")[0])
    monthly_rate = rate_mid / 100 / 12

    if monthly_rate > 0 and loan_tenure > 0:
        emi = (loan_amount * monthly_rate * (1 + monthly_rate)**loan_tenure
               / ((1 + monthly_rate)**loan_tenure - 1))
    else:
        emi = loan_amount / max(loan_tenure, 1)

    total_obligations = emi + (existing_loans * 4500)
    foir       = round((total_obligations / monthly_income) * 100, 1) if monthly_income > 0 else 0
    net_income = monthly_income - monthly_expenses
    ltv        = round((loan_amount / collateral_value) * 100, 1) if collateral_value > 0 else None
    max_ltv    = rules.get("max_ltv")
    ltv_breach = ltv is not None and max_ltv is not None and ltv > max_ltv
    cibil_fail = rules["min_cibil"] > 0 and cibil_score < rules["min_cibil"]

    prompt = f"""You are a senior NBFC credit underwriter with deep knowledge of RBI guidelines,
FOIR norms, CIBIL scoring, and product-specific rules for Indian lending.

LOAN TYPE: {loan_type}
PRODUCT RULES: {rules['key_check']}
TYPICAL INTEREST RANGE: {rules['typical_rate']}%
MAX ALLOWED FOIR: {rules['max_foir']}%
MIN CIBIL REQUIRED: {rules['min_cibil'] if rules['min_cibil'] > 0 else 'Not applicable'}
MAX LTV: {max_ltv}% if applicable

APPLICANT:
- Name: {full_name}, Age: {age}
- Employment: {employment_type}
- Monthly Income: Rs {monthly_income:,.0f}
- Monthly Expenses: Rs {monthly_expenses:,.0f}
- Net Disposable: Rs {net_income:,.0f}
- Business Vintage: {business_vintage} years

LOAN REQUEST:
- Amount: Rs {loan_amount:,.0f}
- Tenure: {loan_tenure} months
- Purpose: {loan_purpose}
- Estimated EMI: Rs {emi:,.0f}
- FOIR: {foir}%
- LTV: {ltv}% (Collateral: Rs {collateral_value:,.0f})

CREDIT PROFILE:
- CIBIL Score: {cibil_score} {'[BELOW MINIMUM]' if cibil_fail else ''}
- Existing Loans: {existing_loans}
- LTV Breach: {'YES' if ltv_breach else 'No'}

Apply product-specific underwriting for {loan_type}.
Respond ONLY with this exact JSON and absolutely no other text:
{{
  "decision": "APPROVED" or "REJECTED" or "CONDITIONAL",
  "risk_level": "LOW" or "MEDIUM" or "HIGH",
  "risk_score": <0-100>,
  "approved_amount": <number or 0>,
  "recommended_interest_rate": <number>,
  "processing_fee": <number>,
  "max_eligible_tenure": <months>,
  "fraud_flags": [],
  "regulatory_flags": [],
  "strengths": ["s1","s2","s3"],
  "concerns": ["c1","c2"],
  "reason": "<2-3 plain English sentences>",
  "recommendation": "<1-2 sentences>",
  "documentation_required": ["doc1","doc2","doc3"]
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}]
        )
        raw    = message.content[0].text.strip().replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error from Claude: {e}")
        return JSONResponse({"error": "AI response parsing failed. Please retry."}, status_code=500)
    except Exception as e:
        logger.error(f"Claude API error: {e}")
        return JSONResponse({"error": f"AI analysis error: {str(e)}"}, status_code=500)

    app_id = generate_app_id()
    result.update({
        "application_id": app_id,
        "loan_type":      loan_type,
        "applicant_name": full_name,
        "loan_amount":    loan_amount,
        "emi_estimate":   round(emi),
        "foir":           foir,
        "ltv":            ltv
    })

    # Persist to PostgreSQL
    if DATABASE_URL:
        try:
            conn = get_db_conn()
            conn.run("""
                INSERT INTO loan_applications (
                    application_id, applicant_name, age, employment_type, loan_type,
                    loan_amount, loan_tenure, cibil_score, monthly_income,
                    decision, risk_level, risk_score, approved_amount, interest_rate,
                    foir, ltv, emi_estimate,
                    fraud_flags, regulatory_flags, strengths, concerns,
                    documentation_required, reason, recommendation
                ) VALUES (
                    :app_id, :name,  :age,  :emp,   :lt,
                    :la,     :tenure,:cibil,:income,
                    :decision,:risk, :score,:approved,:rate,
                    :foir,   :ltv,  :emi,
                    :fraud,  :reg,  :strengths,:concerns,
                    :docs,   :reason,:rec
                )
            """,
                app_id=app_id,        name=full_name,       age=age,
                emp=employment_type,  lt=loan_type,          la=loan_amount,
                tenure=loan_tenure,   cibil=cibil_score,     income=monthly_income,
                decision=result.get("decision"),
                risk=result.get("risk_level"),
                score=result.get("risk_score"),
                approved=result.get("approved_amount", 0),
                rate=result.get("recommended_interest_rate"),
                foir=foir, ltv=ltv, emi=round(emi),
                fraud=json.dumps(result.get("fraud_flags", [])),
                reg=json.dumps(result.get("regulatory_flags", [])),
                strengths=json.dumps(result.get("strengths", [])),
                concerns=json.dumps(result.get("concerns", [])),
                docs=json.dumps(result.get("documentation_required", [])),
                reason=result.get("reason"),
                rec=result.get("recommendation")
            )
            conn.close()
            logger.info(f"✅ Saved application {app_id}")
        except Exception as e:
            logger.error(f"❌ DB save error for {app_id}: {e}")
            # Don't fail the API response — DB save is non-critical

    return JSONResponse(content=result)

# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status":      "ok",
        "service":     "NBFC AI Platform v2.0",
        "loan_types":  len(LOAN_RULES),
        "database":    "connected" if DATABASE_URL else "not configured"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
