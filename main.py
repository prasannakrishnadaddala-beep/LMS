from fastapi import FastAPI, Request, Form, Response, Cookie, UploadFile, File, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import anthropic
import os, json, pg8000.native, ssl, base64, hashlib, secrets, string, random, logging
from urllib.parse import urlparse
from datetime import datetime, timezone
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Env vars ───────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set")

DATABASE_URL   = os.environ.get("DATABASE_URL", "")
SECRET_KEY     = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")

# ── App setup ──────────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="NBFC AI Platform v4.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
templates  = Jinja2Templates(directory="templates")
client     = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
serializer = URLSafeTimedSerializer(SECRET_KEY)

# ── Loan product rules ─────────────────────────────────────────────────────────
LOAN_RULES = {
    "Personal Loan": {
        "max_tenure": 60, "min_cibil": 700, "max_foir": 50,
        "rate_range": [12, 24], "max_ltv": None,
        "key_check": "Income stability and clean credit history are primary. Max FOIR 50%. No secured collateral.",
        "priority_sector": False,
        "docs": ["Salary slips (3 months)", "Bank statement (6 months)", "Form 16", "PAN + Aadhaar", "Office ID / Appointment letter"]
    },
    "Home Loan": {
        "max_tenure": 300, "min_cibil": 650, "max_foir": 55,
        "rate_range": [8.5, 11], "max_ltv": 80,
        "key_check": "LTV max 80% on market value. Legal title clearance, EC for 30 years, approved plan required. RERA registration preferred.",
        "priority_sector": True,
        "docs": ["Sale deed / Agreement to sell", "Property EC (30 yrs)", "Approved building plan", "NOC from builder", "Salary slips (3 months)", "Bank statement (12 months)", "Form 16 / ITR (2 yrs)", "PAN + Aadhaar"]
    },
    "Car Loan": {
        "max_tenure": 84, "min_cibil": 680, "max_foir": 50,
        "rate_range": [9, 14], "max_ltv": 85,
        "key_check": "LTV max 85% on ex-showroom price. Insurance mandatory. Hypothecation in RC book. New vs used vehicle rate differential.",
        "priority_sector": False,
        "docs": ["Vehicle pro-forma invoice", "Insurance quote", "Salary slips / ITR", "Bank statement (6 months)", "PAN + Aadhaar + DL"]
    },
    "Gold Loan": {
        "max_tenure": 12, "min_cibil": 0, "max_foir": 70,
        "rate_range": [9, 18], "max_ltv": 75,
        "key_check": "RBI LTV cap 75% on gold hallmark value. 18-22 karat only. No CIBIL check needed. Income proof optional.",
        "priority_sector": False,
        "docs": ["Gold ornaments / coins for valuation", "PAN + Aadhaar", "Address proof"]
    },
    "Business Loan": {
        "max_tenure": 60, "min_cibil": 680, "max_foir": 60,
        "rate_range": [14, 24], "max_ltv": None,
        "key_check": "Business vintage min 2 years. GST returns (12 months), audited P&L and balance sheet. Banking turnover ratio checked.",
        "priority_sector": False,
        "docs": ["GST returns (12 months)", "ITR (2 yrs)", "Audited financials", "Bank statement (12 months)", "GST certificate", "Business registration / Partnership deed", "PAN + Aadhaar"]
    },
    "Loan Against Property": {
        "max_tenure": 180, "min_cibil": 650, "max_foir": 55,
        "rate_range": [9.5, 14], "max_ltv": 65,
        "key_check": "LTV max 65%. Property must be free of disputes/encumbrances. EC 30 years. Rental income considered at 70% for FOIR. Legal and technical valuation mandatory.",
        "priority_sector": False,
        "docs": ["Property EC (30 yrs)", "Sale deed", "Property tax receipts", "Approved plan", "Bank statement (12 months)", "ITR (3 yrs)", "PAN + Aadhaar"]
    },
    "Two-Wheeler Loan": {
        "max_tenure": 48, "min_cibil": 650, "max_foir": 45,
        "rate_range": [10, 18], "max_ltv": 90,
        "key_check": "LTV max 90%. Local stability of borrower important. Dealer tie-up preferred. Insurance mandatory.",
        "priority_sector": False,
        "docs": ["Vehicle pro-forma invoice", "Salary slip / Income proof", "Bank statement (3 months)", "PAN + Aadhaar + DL"]
    },
    "Education Loan": {
        "max_tenure": 84, "min_cibil": 600, "max_foir": 40,
        "rate_range": [9, 13], "max_ltv": None,
        "key_check": "Institution NAAC/NBA ranking matters. Course employability score. Collateral required above Rs 7.5L (IBA scheme). Co-borrower income primary for FOIR. Moratorium during study + 1 year.",
        "priority_sector": True,
        "docs": ["Admission letter", "Fee structure", "Institution ranking proof", "Co-borrower income proof", "Bank statement (6 months)", "PAN + Aadhaar (student + co-borrower)", "ITR (2 yrs) of co-borrower"]
    },
    "Microfinance / JLG Loan": {
        "max_tenure": 24, "min_cibil": 0, "max_foir": 50,
        "rate_range": [18, 24], "max_ltv": None,
        "key_check": "JLG group of 4-10 members. Household income verification. No overlapping MFI loans per RBI MFIN guidelines. Max outstanding Rs 1.25L per borrower. Rural/semi-urban only.",
        "priority_sector": True,
        "docs": ["Group photograph", "Aadhaar", "Household income declaration", "MFI no-objection certificate", "Gram panchayat / ration card"]
    }
}

# ── Password hashing (stdlib only, no extra deps) ──────────────────────────────
def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
    return f"{salt}:{key.hex()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        salt, key_hex = stored.split(":", 1)
        key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000)
        return secrets.compare_digest(key.hex(), key_hex)
    except Exception:
        return False

# ── Database ───────────────────────────────────────────────────────────────────
def get_db_conn():
    parsed  = urlparse(DATABASE_URL)
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode    = ssl.CERT_NONE
    return pg8000.native.Connection(
        host=parsed.hostname, database=parsed.path.lstrip("/"),
        user=parsed.username, password=parsed.password,
        port=parsed.port or 5432, ssl_context=ssl_ctx
    )

def _run_ddl(conn, sql: str):
    """Run DDL safely, committing immediately."""
    conn.run("COMMIT")
    conn.run(sql)
    conn.run("COMMIT")

def init_db():
    if not DATABASE_URL:
        logger.warning("⚠️  DATABASE_URL not set — running without persistence")
        return
    try:
        conn = get_db_conn()

        # Users table — for multi-bank, multi-user login
        _run_ddl(conn, """
            CREATE TABLE IF NOT EXISTS users (
                id            SERIAL PRIMARY KEY,
                username      VARCHAR(50)  UNIQUE NOT NULL,
                password_hash VARCHAR(300) NOT NULL,
                role          VARCHAR(20)  DEFAULT 'analyst',
                bank_name     VARCHAR(100) DEFAULT 'Default',
                api_key       VARCHAR(64)  UNIQUE,
                is_active     BOOLEAN      DEFAULT TRUE,
                created_at    TIMESTAMPTZ  DEFAULT NOW()
            )
        """)

        # Loan applications table
        _run_ddl(conn, """
            CREATE TABLE IF NOT EXISTS loan_applications (
                id                     SERIAL PRIMARY KEY,
                application_id         VARCHAR(30)   UNIQUE NOT NULL,
                applicant_name         VARCHAR(100),
                age                    INTEGER,
                employment_type        VARCHAR(60),
                employer_name          VARCHAR(100),
                loan_type              VARCHAR(60),
                loan_amount            NUMERIC(15,2),
                loan_tenure            INTEGER,
                cibil_score            INTEGER,
                dpd_30_count           INTEGER       DEFAULT 0,
                dpd_60_count           INTEGER       DEFAULT 0,
                dpd_90_count           INTEGER       DEFAULT 0,
                enquiries_6m           INTEGER       DEFAULT 0,
                credit_vintage_yrs     NUMERIC(4,1)  DEFAULT 0,
                avg_monthly_balance    NUMERIC(15,2) DEFAULT 0,
                bounce_count_6m        INTEGER       DEFAULT 0,
                monthly_income         NUMERIC(15,2),
                itr_income             NUMERIC(15,2) DEFAULT 0,
                gst_turnover           NUMERIC(15,2) DEFAULT 0,
                decision               VARCHAR(20),
                policy_violations      TEXT          DEFAULT '[]',
                risk_level             VARCHAR(10),
                risk_score             INTEGER,
                approved_amount        NUMERIC(15,2),
                interest_rate          NUMERIC(5,2),
                foir                   NUMERIC(5,1),
                ltv                    NUMERIC(5,1),
                emi_estimate           NUMERIC(15,2),
                fraud_flags            TEXT          DEFAULT '[]',
                regulatory_flags       TEXT          DEFAULT '[]',
                strengths              TEXT          DEFAULT '[]',
                concerns               TEXT          DEFAULT '[]',
                documentation_required TEXT          DEFAULT '[]',
                reason                 TEXT,
                recommendation         TEXT,
                counter_offer          TEXT,
                bureau_assessment      TEXT,
                cashflow_assessment    TEXT,
                created_by             VARCHAR(50),
                bank_name              VARCHAR(100),
                cibil_pdf_parsed       BOOLEAN       DEFAULT FALSE,
                created_at             TIMESTAMPTZ   DEFAULT NOW()
            )
        """)

        # Seed admin user if not exists
        existing = conn.run(
            "SELECT COUNT(*) FROM users WHERE username = :u",
            u=ADMIN_USERNAME
        )
        if not existing or existing[0][0] == 0:
            admin_key = secrets.token_hex(32)
            conn.run(
                """INSERT INTO users (username, password_hash, role, bank_name, api_key)
                   VALUES (:u, :h, 'admin', 'NBFC Platform', :k)""",
                u=ADMIN_USERNAME,
                h=hash_password(ADMIN_PASSWORD),
                k=admin_key
            )
            logger.info(f"✅ Admin user seeded. API Key: {admin_key}")
        conn.close()
        logger.info("✅ Database initialized")
    except Exception as e:
        logger.error(f"❌ DB init failed: {e}")

@app.on_event("startup")
async def startup():
    init_db()

# ── Utilities ──────────────────────────────────────────────────────────────────
def generate_app_id() -> str:
    today  = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"LN-{today}-{suffix}"

def verify_session(session) -> dict | None:
    """Returns {username, role, bank_name} or None."""
    if not session:
        return None
    try:
        data = serializer.loads(session, max_age=86400)
        return data if "username" in data else None
    except (BadSignature, SignatureExpired):
        return None

def get_user_from_db(username: str) -> dict | None:
    if not DATABASE_URL:
        return None
    try:
        conn = get_db_conn()
        rows = conn.run(
            "SELECT username, password_hash, role, bank_name, is_active FROM users WHERE username = :u",
            u=username
        )
        conn.close()
        if rows:
            r = rows[0]
            return {"username": r[0], "password_hash": r[1], "role": r[2], "bank_name": r[3], "is_active": r[4]}
    except Exception as e:
        logger.error(f"get_user_from_db: {e}")
    return None

def get_user_from_api_key(api_key: str) -> dict | None:
    if not DATABASE_URL or not api_key:
        return None
    try:
        conn = get_db_conn()
        rows = conn.run(
            "SELECT username, role, bank_name FROM users WHERE api_key = :k AND is_active = TRUE",
            k=api_key
        )
        conn.close()
        if rows:
            r = rows[0]
            return {"username": r[0], "role": r[1], "bank_name": r[2]}
    except Exception as e:
        logger.error(f"get_user_from_api_key: {e}")
    return None

# ── Hard Policy Gate ───────────────────────────────────────────────────────────
def run_policy_gate(data: dict, rules: dict) -> list:
    violations = []
    cibil  = data["cibil_score"]; foir = data["foir"]; age = data["age"]
    lt     = data["loan_type"];   dpd90 = data["dpd_90_count"]
    wo     = data["writeoff_settled"]; enq = data["enquiries_6m"]
    bounce = data["bounce_count_6m"]

    if rules["min_cibil"] > 0 and cibil < rules["min_cibil"]:
        violations.append(f"CIBIL {cibil} below minimum {rules['min_cibil']} for {lt}")
    if foir > rules["max_foir"]:
        violations.append(f"FOIR {foir:.1f}% exceeds product limit of {rules['max_foir']}%")
    if age < 21:
        violations.append("Applicant below minimum age of 21")
    if age > 65:
        violations.append("Applicant exceeds maximum age of 65 at origination")
    if dpd90 > 0:
        violations.append(f"{dpd90} instance(s) of 90+ DPD in last 24 months — hard reject per credit policy")
    if wo:
        violations.append("Write-off or settlement on bureau — hard reject until 3 years clean")
    if enq > 6:
        violations.append(f"{enq} credit enquiries in 6 months — indicates credit hunger")
    if bounce > 3:
        violations.append(f"{bounce} cheque/ECS bounces in 6 months — cash flow stress")
    if lt == "Gold Loan" and data.get("collateral_value", 0) <= 0:
        violations.append("Gold value required for Gold Loan LTV calculation")
    if lt == "Microfinance / JLG Loan" and data["loan_amount"] > 125000:
        violations.append("MFI loan exceeds RBI cap of Rs 1,25,000 per borrower")
    return violations

# ── Risk-based pricing ─────────────────────────────────────────────────────────
def compute_risk_rate(base_rate: float, cibil: int, foir: float, dpd_30: int, enq_6m: int) -> float:
    spread = 0.0
    if cibil >= 800:   spread += 0.0
    elif cibil >= 750: spread += 0.5
    elif cibil >= 700: spread += 1.25
    elif cibil >= 650: spread += 2.5
    else:              spread += 4.0
    if foir > 45: spread += 0.75
    if foir > 55: spread += 1.25
    spread += dpd_30 * 0.5
    if enq_6m > 3: spread += 0.5
    return round(base_rate + spread, 2)

# ── Auth routes ────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    username = username.strip()
    user     = get_user_from_db(username)

    # DB user found — verify against DB
    if user:
        if not user["is_active"]:
            return templates.TemplateResponse("login.html", {"request": request, "error": "Account deactivated. Contact admin."})
        if not verify_password(password, user["password_hash"]):
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials."})
        session_data = {"username": username, "role": user["role"], "bank_name": user["bank_name"]}
    else:
        # Fallback: env-var admin (for no-DB / first run)
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session_data = {"username": username, "role": "admin", "bank_name": "NBFC Platform"}
        else:
            return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials."})

    token = serializer.dumps(session_data)
    resp  = RedirectResponse(url="/", status_code=303)
    resp.set_cookie("session", token, httponly=True, max_age=86400, samesite="lax")
    return resp

@app.post("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("session")
    return resp

# ── Main pages ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home(request: Request, session: str = Cookie(default=None)):
    user = verify_session(session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "loan_types": list(LOAN_RULES.keys()),
        "username": user["username"],
        "role": user.get("role", "analyst"),
        "bank_name": user.get("bank_name", ""),
    })

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, session: str = Cookie(default=None)):
    user = verify_session(session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    stats = {"total": 0, "approved": 0, "rejected": 0, "conditional": 0, "approval_rate": 0.0,
             "avg_cibil": 0, "avg_foir": 0, "avg_loan_amt": 0}
    applications = []
    chart_data   = {"decisions": [], "loan_types": [], "monthly": []}

    if DATABASE_URL:
        try:
            conn = get_db_conn()
            # Scope to bank unless admin
            bank_filter = "" if user.get("role") == "admin" else "WHERE bank_name = :bn"
            params      = {} if user.get("role") == "admin" else {"bn": user.get("bank_name")}

            rows = conn.run(f"""
                SELECT application_id, applicant_name, loan_type, loan_amount,
                       decision, risk_level, risk_score, approved_amount,
                       interest_rate, foir, cibil_score, employment_type, created_at,
                       dpd_30_count, dpd_90_count, enquiries_6m, bounce_count_6m,
                       created_by, bank_name, cibil_pdf_parsed
                FROM loan_applications {bank_filter}
                ORDER BY created_at DESC LIMIT 100
            """, **params)
            for r in rows:
                applications.append({
                    "application_id": r[0], "applicant_name": r[1],
                    "loan_type": r[2],      "loan_amount": float(r[3] or 0),
                    "decision": r[4],       "risk_level": r[5],
                    "risk_score": r[6],     "approved_amount": float(r[7] or 0),
                    "interest_rate": float(r[8] or 0), "foir": float(r[9] or 0),
                    "cibil_score": r[10],   "employment_type": r[11],
                    "created_at": r[12].strftime("%d %b %Y, %I:%M %p") if r[12] else "",
                    "dpd_30_count": r[13],  "dpd_90_count": r[14],
                    "enquiries_6m": r[15],  "bounce_count_6m": r[16],
                    "created_by": r[17],    "bank_name": r[18],
                    "cibil_pdf_parsed": r[19],
                })

            counts = conn.run(f"""
                SELECT
                    COUNT(*),
                    COUNT(*) FILTER (WHERE decision='APPROVED'),
                    COUNT(*) FILTER (WHERE decision='REJECTED'),
                    COUNT(*) FILTER (WHERE decision='CONDITIONAL'),
                    ROUND(AVG(cibil_score)::numeric, 0),
                    ROUND(AVG(foir)::numeric, 1),
                    ROUND(AVG(loan_amount)::numeric, 0)
                FROM loan_applications {bank_filter}
            """, **params)
            if counts:
                t, a, r_, c, ac, af, al = counts[0]
                t = int(t or 0); a = int(a or 0)
                stats = {
                    "total": t, "approved": a,
                    "rejected": int(r_ or 0), "conditional": int(c or 0),
                    "approval_rate": round((a/t*100) if t > 0 else 0, 1),
                    "avg_cibil": int(ac or 0), "avg_foir": float(af or 0),
                    "avg_loan_amt": int(al or 0),
                }

            # Chart data: decision breakdown
            chart_data["decisions"] = [
                {"label": "Approved", "value": stats["approved"], "color": "#1a7f5a"},
                {"label": "Rejected", "value": stats["rejected"], "color": "#c0392b"},
                {"label": "Conditional", "value": stats["conditional"], "color": "#c17f24"},
            ]
            # Chart data: loan type breakdown
            lt_rows = conn.run(f"""
                SELECT loan_type, COUNT(*) as cnt
                FROM loan_applications {bank_filter}
                GROUP BY loan_type ORDER BY cnt DESC
            """, **params)
            chart_data["loan_types"] = [{"label": r[0], "value": int(r[1])} for r in lt_rows]

            # Chart data: last 7 days
            day_rows = conn.run(f"""
                SELECT DATE(created_at) as d, COUNT(*) as cnt,
                       COUNT(*) FILTER (WHERE decision='APPROVED') as app
                FROM loan_applications {bank_filter}
                WHERE created_at >= NOW() - INTERVAL '7 days'
                GROUP BY d ORDER BY d
            """, **params)
            chart_data["monthly"] = [{"date": str(r[0]), "total": int(r[1]), "approved": int(r[2])} for r in day_rows]

            conn.close()
        except Exception as e:
            logger.error(f"Dashboard error: {e}")

    return templates.TemplateResponse("dashboard.html", {
        "request": request, "username": user["username"],
        "role": user.get("role", "analyst"),
        "bank_name": user.get("bank_name", ""),
        "stats": stats, "applications": applications,
        "chart_data_json": json.dumps(chart_data),
    })

# ── Admin: User management ─────────────────────────────────────────────────────
@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, session: str = Cookie(default=None)):
    user = verify_session(session)
    if not user or user.get("role") != "admin":
        return RedirectResponse(url="/", status_code=303)
    users_list = []
    if DATABASE_URL:
        try:
            conn = get_db_conn()
            rows = conn.run(
                "SELECT username, role, bank_name, api_key, is_active, created_at FROM users ORDER BY created_at DESC"
            )
            conn.close()
            for r in rows:
                users_list.append({
                    "username": r[0], "role": r[1], "bank_name": r[2],
                    "api_key": r[3], "is_active": r[4],
                    "created_at": r[5].strftime("%d %b %Y") if r[5] else ""
                })
        except Exception as e:
            logger.error(f"admin_users: {e}")
    return templates.TemplateResponse("admin_users.html", {
        "request": request, "username": user["username"],
        "users": users_list
    })

@app.post("/admin/users/create")
def create_user(
    request: Request,
    session: str  = Cookie(default=None),
    username: str = Form(...),
    password: str = Form(...),
    role: str     = Form("analyst"),
    bank_name: str= Form("Default"),
):
    user = verify_session(session)
    if not user or user.get("role") != "admin":
        return JSONResponse({"error": "Forbidden"}, status_code=403)
    if not DATABASE_URL:
        return JSONResponse({"error": "No database configured."}, status_code=500)
    try:
        api_key = secrets.token_hex(32)
        conn    = get_db_conn()
        conn.run(
            """INSERT INTO users (username, password_hash, role, bank_name, api_key)
               VALUES (:u, :h, :r, :b, :k)""",
            u=username.strip(), h=hash_password(password),
            r=role, b=bank_name.strip(), k=api_key
        )
        conn.close()
        return RedirectResponse(url="/admin/users", status_code=303)
    except Exception as e:
        logger.error(f"create_user: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

# ── CIBIL PDF Parser ───────────────────────────────────────────────────────────
@app.post("/parse-cibil")
@limiter.limit("5/minute")
async def parse_cibil(
    request: Request,
    session: str  = Cookie(default=None),
    file: UploadFile = File(...),
):
    user = verify_session(session)
    if not user:
        return JSONResponse({"error": "Session expired. Please log in again."}, status_code=401)

    # Validate file
    fname = (file.filename or "").lower()
    if not fname.endswith(".pdf"):
        return JSONResponse({"error": "Please upload a CIBIL report PDF file."}, status_code=400)

    content = await file.read()
    if len(content) > 15 * 1024 * 1024:  # 15 MB limit
        return JSONResponse({"error": "PDF too large. Maximum size is 15 MB."}, status_code=400)
    if len(content) < 1000:
        return JSONResponse({"error": "PDF appears to be empty or corrupted."}, status_code=400)

    b64 = base64.standard_b64encode(content).decode("utf-8")

    extraction_prompt = """You are an expert CIBIL/credit bureau data extraction system for Indian lenders.
Carefully read this credit report and extract every available data point.

Return ONLY valid JSON — no explanation, no markdown, no preamble:
{
  "cibil_score": <integer 300-900, or null if not found>,
  "credit_vintage_yrs": <float, age of oldest credit account in years, e.g. 6.5, default 0>,
  "enquiries_6m": <integer, hard enquiries in last 6 months, default 0>,
  "dpd_30_count": <integer, accounts with 30+ DPD in last 24 months, default 0>,
  "dpd_60_count": <integer, accounts with 60+ DPD in last 24 months, default 0>,
  "dpd_90_count": <integer, accounts with 90+ DPD in last 24 months, default 0>,
  "writeoff_settled": <"yes" if any account shows written-off/settled/suit-filed status, else "no">,
  "secured_unsecured_ratio": <one of: "Mostly secured (home/car loans)" | "Mix of secured and unsecured" | "Mostly unsecured (personal/credit card)" | "Only unsecured loans" | "First-time borrower">,
  "existing_emi_total": <estimated total active monthly EMI obligations in rupees, default 0>,
  "total_active_loans": <integer, number of active loan accounts>,
  "total_credit_cards": <integer, number of active credit cards>,
  "credit_limit_total": <total credit card limit in rupees, default 0>,
  "overdue_amount": <total current overdue amount in rupees, default 0>,
  "name_on_report": <full name as on report, or "">,
  "pan_masked": <masked PAN if visible, or "">,
  "report_date": <report generation date as string, or "">,
  "extraction_notes": <string, max 150 chars, any important observations e.g. "3 active personal loans", "guarantor accounts present">
}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1200,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/pdf",
                            "data": b64,
                        }
                    },
                    {"type": "text", "text": extraction_prompt}
                ]
            }]
        )
        raw    = message.content[0].text.strip()
        raw    = raw.replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
        logger.info(f"CIBIL parsed by {user['username']}: score={result.get('cibil_score')}")
        return JSONResponse(content={"ok": True, "data": result})
    except json.JSONDecodeError as e:
        logger.error(f"CIBIL JSON parse error: {e}")
        return JSONResponse({"error": "Could not extract structured data from this PDF. Ensure it is a valid CIBIL/bureau report."}, status_code=422)
    except Exception as e:
        logger.error(f"CIBIL parse exception: {e}")
        return JSONResponse({"error": "PDF parsing failed. Please try again."}, status_code=500)

# ── Bank Statement PDF Parser ──────────────────────────────────────────────────
@app.post("/parse-bank-statement")
@limiter.limit("5/minute")
async def parse_bank_statement(
    request: Request,
    session: str  = Cookie(default=None),
    file: UploadFile = File(...),
):
    user = verify_session(session)
    if not user:
        return JSONResponse({"error": "Session expired. Please log in again."}, status_code=401)

    fname = (file.filename or "").lower()
    if not fname.endswith(".pdf"):
        return JSONResponse({"error": "Please upload a bank statement PDF file."}, status_code=400)

    content = await file.read()
    if len(content) > 20 * 1024 * 1024:
        return JSONResponse({"error": "PDF too large. Maximum size is 20 MB."}, status_code=400)
    if len(content) < 500:
        return JSONResponse({"error": "PDF appears to be empty or corrupted."}, status_code=400)

    b64 = base64.standard_b64encode(content).decode("utf-8")

    extraction_prompt = """You are an expert Indian bank statement analysis system for NBFC credit underwriting.
Analyze this bank statement carefully and extract all financial signals relevant to loan underwriting.

Return ONLY valid JSON — no explanation, no markdown, no preamble:
{
  "avg_monthly_balance": <average end-of-day balance over all months, in rupees, default 0>,
  "min_monthly_balance": <lowest monthly closing balance seen, in rupees, default 0>,
  "max_monthly_balance": <highest monthly closing balance seen, in rupees, default 0>,
  "avg_monthly_credit": <average total credits (inflows) per month in rupees, default 0>,
  "avg_monthly_debit": <average total debits (outflows) per month in rupees, default 0>,
  "bounce_count": <total number of bounced/returned cheques or ECS/NACH returns in the statement period, default 0>,
  "salary_credits_count": <number of months with regular salary credit detected, default 0>,
  "salary_amount": <detected monthly salary credit amount if consistent, else 0>,
  "salary_credit_regular": <true if salary credited on similar dates each month, else false>,
  "emi_debits_detected": <estimated total monthly EMI/loan debit outflows in rupees, default 0>,
  "emi_accounts_count": <number of distinct loan EMI debits detected, default 0>,
  "cash_withdrawals_monthly_avg": <average monthly cash withdrawal amount, default 0>,
  "upi_credits_monthly_avg": <average monthly UPI/NEFT inflow from business/clients, default 0>,
  "statement_months": <number of months covered by this statement, default 0>,
  "bank_name": <bank name as appearing on statement, or "">,
  "account_holder": <account holder name, or "">,
  "account_type": <"Savings" or "Current" or "OD" or "">,
  "closing_balance": <most recent closing balance in the statement, default 0>,
  "inward_cheque_returns": <number of inward cheque/ECS returns — indicates bad debtors if current account, default 0>,
  "outward_cheque_returns": <number of outward cheque/ECS/NACH returns — indicates payment defaults, default 0>,
  "large_unusual_credits": <number of unusually large one-time credits that don't match salary pattern, default 0>,
  "credit_debit_ratio": <round(avg_monthly_credit / avg_monthly_debit, 2) if debit > 0 else null>,
  "extraction_notes": <string max 200 chars — key observations like "GST credits visible", "2 loan EMIs detected", "irregular salary">
}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1500,
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/pdf",
                            "data": b64,
                        }
                    },
                    {"type": "text", "text": extraction_prompt}
                ]
            }]
        )
        raw    = message.content[0].text.strip()
        raw    = raw.replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
        logger.info(f"Bank statement parsed by {user['username']}: AMB=₹{result.get('avg_monthly_balance')}")
        return JSONResponse(content={"ok": True, "data": result})
    except json.JSONDecodeError as e:
        logger.error(f"Bank statement JSON parse error: {e}")
        return JSONResponse({"error": "Could not extract structured data. Ensure this is a valid bank statement PDF."}, status_code=422)
    except Exception as e:
        logger.error(f"Bank statement parse exception: {e}")
        return JSONResponse({"error": "PDF parsing failed. Please try again."}, status_code=500)


# ── Fraud Rule Engine ──────────────────────────────────────────────────────────
def run_fraud_gate(data: dict) -> list:
    """
    Rule-based pre-AI fraud detection engine.
    Returns list of fraud flag strings. Empty list = clean.
    """
    flags = []
    income        = data.get("monthly_income", 0)
    amb           = data.get("avg_monthly_balance", 0)
    itr_income    = data.get("itr_income", 0)
    gst_turnover  = data.get("gst_turnover", 0)
    loan_amount   = data.get("loan_amount", 0)
    cibil_score   = data.get("cibil_score", 0)
    enquiries_6m  = data.get("enquiries_6m", 0)
    bounce_count  = data.get("bounce_count_6m", 0)
    emp_type      = data.get("employment_type", "")
    employer      = data.get("employer_name", "").lower()
    loan_purpose  = data.get("loan_purpose", "").lower()
    dpd_30        = data.get("dpd_30_count", 0)
    dpd_90        = data.get("dpd_90_count", 0)
    wo            = data.get("writeoff_settled", False)
    vintage       = data.get("credit_vintage_yrs", 0)
    existing_emi  = data.get("existing_emi_total", 0)
    bs_parsed     = data.get("bank_statement_parsed", False)
    bs_salary     = data.get("bs_salary_amount", 0)
    bs_bounce     = data.get("bs_bounce_count", 0)
    bs_amb        = data.get("bs_avg_monthly_balance", 0)
    bs_emi_debits = data.get("bs_emi_debits_detected", 0)
    large_credits = data.get("bs_large_unusual_credits", 0)

    # ── Income Inflation Detection ──────────────────────────────────────────
    if itr_income > 0 and income > 0:
        declared_annual = income * 12
        if declared_annual > itr_income * 2.5:
            flags.append(f"Income inflation risk: declared ₹{income:,.0f}/mo but ITR shows ₹{itr_income/12:,.0f}/mo annualised")

    if bs_parsed and bs_salary > 0 and income > 0:
        if income > bs_salary * 1.5:
            flags.append(f"Salary mismatch: declared ₹{income:,.0f}/mo but bank credits show ₹{bs_salary:,.0f}/mo")

    # ── AMB vs Income Mismatch ──────────────────────────────────────────────
    if amb > 0 and income > 0:
        # AMB should be at least 1-2 months income for stable borrower
        if amb < income * 0.3 and income > 50000:
            flags.append(f"Very low AMB (₹{amb:,.0f}) relative to declared income (₹{income:,.0f}/mo) — possible income overstatement")

    if bs_parsed and bs_amb > 0 and amb > 0:
        if abs(bs_amb - amb) / max(amb, 1) > 0.5:
            flags.append(f"AMB discrepancy: declared ₹{amb:,.0f} vs bank statement shows ₹{bs_amb:,.0f}")

    # ── Hidden EMI Detection ────────────────────────────────────────────────
    if bs_parsed and bs_emi_debits > 0 and existing_emi > 0:
        if bs_emi_debits > existing_emi * 1.5:
            flags.append(f"Undisclosed EMIs: bank statement shows ₹{bs_emi_debits:,.0f}/mo EMI debits vs declared ₹{existing_emi:,.0f}/mo")
    elif bs_parsed and bs_emi_debits > 0 and existing_emi == 0:
        if bs_emi_debits > 5000:
            flags.append(f"Undisclosed EMIs: bank statement shows ₹{bs_emi_debits:,.0f}/mo EMI debits but applicant declared none")

    # ── Unusual Credit Patterns ─────────────────────────────────────────────
    if bs_parsed and large_credits >= 3:
        flags.append(f"{large_credits} large one-time credits in bank statement — verify source, possible window dressing")

    # ── Credit Hunger Pattern ───────────────────────────────────────────────
    if enquiries_6m >= 8:
        flags.append(f"Extreme credit hunger: {enquiries_6m} bureau enquiries in 6 months — possible multiple simultaneous applications")
    elif enquiries_6m >= 5 and (dpd_30 > 0 or bounce_count > 0):
        flags.append(f"Credit hunger + stress signals: {enquiries_6m} enquiries with existing delinquencies")

    # ── Bounce Escalation ───────────────────────────────────────────────────
    if bs_parsed and bs_bounce > bounce_count + 2:
        flags.append(f"Bounce underreporting: declared {bounce_count} bounces but bank statement shows {bs_bounce}")

    # ── Loan Amount vs Income Ratio ─────────────────────────────────────────
    if income > 0 and loan_amount > income * 60:
        flags.append(f"Loan amount (₹{loan_amount:,.0f}) is {loan_amount/income:.0f}x monthly income — extremely high leverage")

    # ── Rapid CIBIL + Behaviour Mismatch ───────────────────────────────────
    if cibil_score >= 750 and dpd_90 > 0:
        flags.append("CIBIL score inconsistent with 90+ DPD history — verify bureau report authenticity")

    if cibil_score >= 780 and wo:
        flags.append("High CIBIL score with write-off history — possible stale or manipulated bureau data")

    # ── First-time Borrower with High Loan ─────────────────────────────────
    if vintage == 0 and loan_amount > 500000:
        flags.append(f"First-time borrower requesting ₹{loan_amount:,.0f} with zero credit history — verify income thoroughly")

    # ── GST vs Income Mismatch for Business ────────────────────────────────
    if "business" in emp_type.lower() or "self-employed" in emp_type.lower():
        if gst_turnover > 0 and income > 0:
            implied_monthly = gst_turnover / 12
            if income > implied_monthly * 0.5:
                flags.append(f"High income-to-turnover ratio: declared ₹{income:,.0f}/mo income from ₹{gst_turnover/12:,.0f}/mo GST turnover")

    return flags


# ── REST API — for LMS / MuleSoft integration ─────────────────────────────────
@app.post("/api/v1/analyze")
@limiter.limit("20/minute")
async def api_analyze(request: Request, x_api_key: str = Header(default="")):
    """Programmatic API for LMS integration. Accepts JSON body."""
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key header."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    # Map JSON body to same logic as form endpoint
    required = ["full_name", "age", "employment_type", "monthly_income",
                "monthly_expenses", "cibil_score", "loan_amount", "loan_tenure",
                "loan_type", "loan_purpose"]
    missing = [f for f in required if f not in body]
    if missing:
        return JSONResponse({"error": f"Missing required fields: {missing}"}, status_code=400)

    # Delegate to core logic
    result = _run_analysis(body, api_user)
    return JSONResponse(content=result)

# ── Core loan analysis (shared by form + API) ──────────────────────────────────
@app.post("/analyze-loan")
@limiter.limit("10/minute")
def analyze_loan(
    request:              Request,
    session:              str   = Cookie(default=None),
    full_name:            str   = Form(...),
    age:                  int   = Form(...),
    employment_type:      str   = Form(...),
    employer_name:        str   = Form(""),
    employer_vintage_yrs: float = Form(0),
    monthly_income:       float = Form(...),
    monthly_expenses:     float = Form(...),
    itr_income:           float = Form(0),
    gst_turnover:         float = Form(0),
    cibil_score:          int   = Form(...),
    dpd_30_count:         int   = Form(0),
    dpd_60_count:         int   = Form(0),
    dpd_90_count:         int   = Form(0),
    writeoff_settled:     str   = Form("no"),
    enquiries_6m:         int   = Form(0),
    credit_vintage_yrs:   float = Form(0),
    secured_unsecured_ratio: str= Form(""),
    avg_monthly_balance:  float = Form(0),
    bounce_count_6m:      int   = Form(0),
    salary_credits_regular: str = Form("yes"),
    existing_emi_total:   float = Form(0),
    loan_amount:          float = Form(...),
    loan_tenure:          int   = Form(...),
    loan_type:            str   = Form(...),
    loan_purpose:         str   = Form(...),
    collateral_value:     float = Form(0),
    business_vintage_yrs: float = Form(0),
    cibil_pdf_parsed:     str   = Form("no"),
):
    user = verify_session(session)
    if not user:
        return JSONResponse({"error": "Session expired. Please log in again."}, status_code=401)

    body = {
        "full_name": full_name, "age": age, "employment_type": employment_type,
        "employer_name": employer_name, "employer_vintage_yrs": employer_vintage_yrs,
        "monthly_income": monthly_income, "monthly_expenses": monthly_expenses,
        "itr_income": itr_income, "gst_turnover": gst_turnover,
        "cibil_score": cibil_score, "dpd_30_count": dpd_30_count,
        "dpd_60_count": dpd_60_count, "dpd_90_count": dpd_90_count,
        "writeoff_settled": writeoff_settled, "enquiries_6m": enquiries_6m,
        "credit_vintage_yrs": credit_vintage_yrs,
        "secured_unsecured_ratio": secured_unsecured_ratio,
        "avg_monthly_balance": avg_monthly_balance, "bounce_count_6m": bounce_count_6m,
        "salary_credits_regular": salary_credits_regular,
        "existing_emi_total": existing_emi_total, "loan_amount": loan_amount,
        "loan_tenure": loan_tenure, "loan_type": loan_type,
        "loan_purpose": loan_purpose, "collateral_value": collateral_value,
        "business_vintage_yrs": business_vintage_yrs,
        "cibil_pdf_parsed": cibil_pdf_parsed.lower() in ("yes","true","1"),
    }
    result = _run_analysis(body, user)
    return JSONResponse(content=result)


def _run_analysis(body: dict, user: dict) -> dict:
    full_name     = str(body.get("full_name", "")).strip()[:100]
    age           = int(body.get("age", 0))
    employment_type = str(body.get("employment_type", ""))
    employer_name = str(body.get("employer_name", "")).strip()[:100]
    employer_vintage_yrs = float(body.get("employer_vintage_yrs", 0))
    monthly_income = float(body.get("monthly_income", 0))
    monthly_expenses = float(body.get("monthly_expenses", 0))
    itr_income    = float(body.get("itr_income", 0))
    gst_turnover  = float(body.get("gst_turnover", 0))
    cibil_score   = int(body.get("cibil_score", 300))
    dpd_30_count  = int(body.get("dpd_30_count", 0))
    dpd_60_count  = int(body.get("dpd_60_count", 0))
    dpd_90_count  = int(body.get("dpd_90_count", 0))
    wo_bool       = str(body.get("writeoff_settled","no")).lower() in ("yes","true","1","on")
    enquiries_6m  = int(body.get("enquiries_6m", 0))
    credit_vintage_yrs = float(body.get("credit_vintage_yrs", 0))
    secured_unsecured_ratio = str(body.get("secured_unsecured_ratio",""))
    avg_monthly_balance = float(body.get("avg_monthly_balance", 0))
    bounce_count_6m = int(body.get("bounce_count_6m", 0))
    sal_reg_bool  = str(body.get("salary_credits_regular","yes")).lower() in ("yes","true","1","on")
    existing_emi_total = float(body.get("existing_emi_total", 0))
    loan_amount   = float(body.get("loan_amount", 0))
    loan_tenure   = int(body.get("loan_tenure", 12))
    loan_type     = str(body.get("loan_type", ""))
    loan_purpose  = str(body.get("loan_purpose", "")).strip()[:300]
    collateral_value = float(body.get("collateral_value", 0))
    business_vintage_yrs = float(body.get("business_vintage_yrs", 0))
    cibil_pdf_parsed    = bool(body.get("cibil_pdf_parsed", False))
    bank_stmt_parsed    = bool(body.get("bank_statement_parsed", False))
    bs_salary_amount    = float(body.get("bs_salary_amount", 0))
    bs_avg_balance      = float(body.get("bs_avg_monthly_balance", 0))
    bs_bounce_count     = int(body.get("bs_bounce_count", 0))
    bs_emi_debits       = float(body.get("bs_emi_debits_detected", 0))
    bs_large_credits    = int(body.get("bs_large_unusual_credits", 0))
    bs_cd_ratio         = float(body.get("bs_credit_debit_ratio", 0) or 0)
    bs_stmt_months      = int(body.get("bs_statement_months", 0))
    bs_upi_credits      = float(body.get("bs_upi_credits_monthly_avg", 0))

    # Bank statement overrides manual inputs when available
    if bank_stmt_parsed:
        if bs_avg_balance > 0:
            avg_monthly_balance = bs_avg_balance
        if bs_bounce_count > bounce_count_6m:
            bounce_count_6m = bs_bounce_count
        if bs_emi_debits > existing_emi_total:
            existing_emi_total = bs_emi_debits

    if loan_type not in LOAN_RULES:
        return {"error": "Invalid loan type."}

    rules = LOAN_RULES[loan_type]

    # EMI & FOIR
    rate_mid     = (rules["rate_range"][0] + rules["rate_range"][1]) / 2
    monthly_rate = rate_mid / 100 / 12
    if monthly_rate > 0 and loan_tenure > 0:
        emi = (loan_amount * monthly_rate * (1 + monthly_rate)**loan_tenure
               / ((1 + monthly_rate)**loan_tenure - 1))
    else:
        emi = loan_amount / max(loan_tenure, 1)

    total_obligations = emi + existing_emi_total
    foir       = round((total_obligations / monthly_income) * 100, 1) if monthly_income > 0 else 0
    net_income = monthly_income - monthly_expenses
    ltv        = round((loan_amount / collateral_value) * 100, 1) if collateral_value > 0 else None
    max_ltv    = rules.get("max_ltv")
    ltv_breach = ltv is not None and max_ltv is not None and ltv > max_ltv

    income_gap = ""
    if itr_income > 0 and monthly_income > 0:
        ratio = itr_income / (monthly_income * 12)
        if ratio < 0.7:
            income_gap = f"ITR income Rs {itr_income:,.0f}/yr is only {ratio*100:.0f}% of declared income annualised"

    computed_rate = compute_risk_rate(rules["rate_range"][0], cibil_score, foir, dpd_30_count, enquiries_6m)

    # Policy gate
    gate_data = {
        "cibil_score": cibil_score, "foir": foir, "age": age, "loan_type": loan_type,
        "dpd_90_count": dpd_90_count, "writeoff_settled": wo_bool,
        "enquiries_6m": enquiries_6m, "bounce_count_6m": bounce_count_6m,
        "collateral_value": collateral_value, "loan_amount": loan_amount
    }
    policy_violations = run_policy_gate(gate_data, rules)

    # Fraud engine
    fraud_gate_data = {
        "monthly_income": monthly_income, "avg_monthly_balance": avg_monthly_balance,
        "itr_income": itr_income, "gst_turnover": gst_turnover,
        "loan_amount": loan_amount, "cibil_score": cibil_score,
        "enquiries_6m": enquiries_6m, "bounce_count_6m": bounce_count_6m,
        "employment_type": employment_type, "employer_name": employer_name,
        "loan_purpose": loan_purpose, "dpd_30_count": dpd_30_count,
        "dpd_90_count": dpd_90_count, "writeoff_settled": wo_bool,
        "credit_vintage_yrs": credit_vintage_yrs, "existing_emi_total": existing_emi_total,
        "bank_statement_parsed": bank_stmt_parsed,
        "bs_salary_amount": bs_salary_amount, "bs_avg_monthly_balance": bs_avg_balance,
        "bs_bounce_count": bs_bounce_count, "bs_emi_debits_detected": bs_emi_debits,
        "bs_large_unusual_credits": bs_large_credits,
    }
    pre_fraud_flags = run_fraud_gate(fraud_gate_data)

    app_id = generate_app_id()

    if policy_violations:
        result = {
            "application_id": app_id, "decision": "REJECTED",
            "risk_level": "HIGH", "risk_score": 95,
            "approved_amount": 0, "recommended_interest_rate": 0,
            "processing_fee": 0, "max_eligible_tenure": 0,
            "fraud_flags": pre_fraud_flags, "regulatory_flags": [],
            "bureau_assessment": f"CIBIL {cibil_score}. DPD 90+: {dpd_90_count}. Enquiries 6m: {enquiries_6m}.",
            "cashflow_assessment": f"FOIR: {foir}%. AMB: Rs {avg_monthly_balance:,.0f}. Bounces: {bounce_count_6m}.{'  [Bank statement verified]' if bank_stmt_parsed else ''}",
            "strengths": [], "concerns": policy_violations,
            "policy_violations": policy_violations,
            "reason": "Declined at policy screening. Hard rules triggered: " + " | ".join(policy_violations),
            "recommendation": "Resolve policy violations before reapplying." + (f" Note: {len(pre_fraud_flags)} fraud signals detected — investigate before any reconsideration." if pre_fraud_flags else ""),
            "documentation_required": rules["docs"],
            "counter_offer": None,
            "loan_type": loan_type, "applicant_name": full_name,
            "loan_amount": loan_amount, "emi_estimate": round(emi),
            "foir": foir, "ltv": ltv, "computed_rate": computed_rate,
            "cibil_pdf_parsed": cibil_pdf_parsed,
            "bank_statement_parsed": bank_stmt_parsed,
        }
        _save(result, age, employment_type, employer_name, loan_tenure, cibil_score,
              monthly_income, itr_income, gst_turnover, dpd_30_count, dpd_60_count,
              dpd_90_count, enquiries_6m, credit_vintage_yrs, avg_monthly_balance,
              bounce_count_6m, ltv, user, cibil_pdf_parsed)
        return result

    btr = "N/A"
    if gst_turnover > 0 and avg_monthly_balance > 0:
        btr = f"{round((avg_monthly_balance * 12) / gst_turnover * 100, 1)}%"

    bureau_source = "CIBIL report PDF (auto-extracted)" if cibil_pdf_parsed else "manually entered"
    bs_source     = "Bank statement PDF (auto-extracted)" if bank_stmt_parsed else "manually entered"

    bs_section = ""
    if bank_stmt_parsed:
        bs_section = f"""
BANK STATEMENT ANALYSIS ({bs_source}, {bs_stmt_months} months):
- Avg monthly balance: Rs {bs_avg_balance:,.0f} | Credit/Debit ratio: {bs_cd_ratio}
- Salary credit detected: Rs {bs_salary_amount:,.0f}/mo {'[MATCHES DECLARED]' if abs(bs_salary_amount - monthly_income) < monthly_income * 0.2 else '[MISMATCH WITH DECLARED]'}
- EMI debits detected: Rs {bs_emi_debits:,.0f}/mo across estimated {body.get('bs_emi_accounts_count',0)} accounts
- Bounces (outward): {bs_bounce_count} | UPI/NEFT business credits: Rs {bs_upi_credits:,.0f}/mo avg
- Unusual large credits: {bs_large_credits} instances {'[VERIFY SOURCE]' if bs_large_credits >= 3 else ''}"""

    fraud_section = ""
    if pre_fraud_flags:
        fraud_section = f"""
⚠️ PRE-SCREENING FRAUD FLAGS (rule-based engine — {len(pre_fraud_flags)} flag(s)):
{chr(10).join('- ' + f for f in pre_fraud_flags)}
These flags were generated before AI analysis. You MUST address each one in your assessment."""

    prompt = f"""You are a Senior Credit Manager at a leading Indian NBFC with 15+ years experience.
You follow RBI Master Directions and produce structured credit assessments like real banks do.
Bureau data source: {bureau_source}

LOAN: {loan_type} | Rate range: {rules['rate_range'][0]}%-{rules['rate_range'][1]}% | Risk-computed rate: {computed_rate}%
Policy: Max FOIR {rules['max_foir']}% | Min CIBIL {rules['min_cibil'] if rules['min_cibil'] > 0 else 'N/A'} | Max LTV {max_ltv}% | Max Tenure {rules['max_tenure']}m | Priority Sector: {'YES' if rules['priority_sector'] else 'NO'}
Underwriting note: {rules['key_check']}

APPLICANT: {full_name}, Age {age}, {employment_type}
Employer: {employer_name or 'Not specified'} | Employer vintage: {employer_vintage_yrs}y | Business vintage: {business_vintage_yrs}y {'[BELOW 2yr min for BL]' if loan_type == 'Business Loan' and business_vintage_yrs < 2 else ''}

INCOME & CASHFLOW:
- Declared monthly income: Rs {monthly_income:,.0f} | Expenses: Rs {monthly_expenses:,.0f} | Net disposable: Rs {net_income:,.0f}
- ITR income (annual): Rs {itr_income:,.0f} {('[INCOME GAP: ' + income_gap + ']') if income_gap else ''}
- GST turnover (annual): Rs {gst_turnover:,.0f} | Banking turnover ratio: {btr}
- Avg monthly bank balance: Rs {avg_monthly_balance:,.0f}{'  [from bank statement]' if bank_stmt_parsed else ''}
- Salary/credit regularity: {'Regular' if sal_reg_bool else 'IRREGULAR'}
- Cheque/ECS bounces (6m): {bounce_count_6m} {'[CAUTION]' if bounce_count_6m > 1 else ''}
{bs_section}
BUREAU ({bureau_source}):
- CIBIL: {cibil_score} | Credit vintage: {credit_vintage_yrs}y | Secured/unsecured mix: {secured_unsecured_ratio or 'N/A'}
- DPD 30+: {dpd_30_count} | DPD 60+: {dpd_60_count} | DPD 90+: {dpd_90_count}
- Write-off/settlement: {'YES' if wo_bool else 'None'} | Enquiries (6m): {enquiries_6m} {'[HIGH]' if enquiries_6m > 3 else ''}
- Existing EMI obligations: Rs {existing_emi_total:,.0f}/month{'  [detected from bank statement]' if bank_stmt_parsed and bs_emi_debits > 0 else ''}

LOAN REQUEST:
- Amount: Rs {loan_amount:,.0f} | Tenure: {loan_tenure}m | Purpose: {loan_purpose}
- EMI estimate: Rs {emi:,.0f} | FOIR post-EMI: {foir}% {'[EXCEEDS LIMIT]' if foir > rules['max_foir'] else '[OK]'}
- Collateral: Rs {collateral_value:,.0f} | LTV: {str(ltv)+'%' if ltv else 'N/A'} {'[LTV BREACH]' if ltv_breach else ''}
{fraud_section}
Respond ONLY with this JSON (no other text):
{{
  "decision": "APPROVED" or "REJECTED" or "CONDITIONAL",
  "risk_level": "LOW" or "MEDIUM" or "HIGH",
  "risk_score": <0-100>,
  "approved_amount": <number or 0>,
  "recommended_interest_rate": {computed_rate},
  "processing_fee": <rupee amount>,
  "max_eligible_tenure": <months>,
  "fraud_flags": {json.dumps(pre_fraud_flags)},
  "regulatory_flags": [],
  "bureau_assessment": "<2-3 sentences on bureau quality>",
  "cashflow_assessment": "<2-3 sentences on income, banking, FOIR — mention bank statement verification if present>",
  "strengths": ["s1","s2","s3"],
  "concerns": ["c1","c2"],
  "policy_violations": [],
  "reason": "<3-4 plain English sentences covering all key factors including any fraud flags>",
  "recommendation": "<specific action for credit committee or processing officer>",
  "counter_offer": "<if REJECTED: what amount/tenure/conditions would work, or null>",
  "documentation_required": {json.dumps(rules['docs'])}
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )
        raw    = message.content[0].text.strip().replace("```json","").replace("```","").strip()
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(f"JSON parse error: {e}")
        return {"error": "AI response parsing failed. Retry."}
    except Exception as e:
        logger.error(f"Claude error: {e}")
        return {"error": str(e)}

    result.update({
        "application_id": app_id, "loan_type": loan_type,
        "applicant_name": full_name, "loan_amount": loan_amount,
        "emi_estimate": round(emi), "foir": foir,
        "ltv": ltv, "computed_rate": computed_rate, "policy_violations": [],
        "cibil_pdf_parsed": cibil_pdf_parsed,
        "bank_statement_parsed": bank_stmt_parsed,
        "fraud_flags": result.get("fraud_flags", pre_fraud_flags),
    })
    _save(result, age, employment_type, employer_name, loan_tenure, cibil_score,
          monthly_income, itr_income, gst_turnover, dpd_30_count, dpd_60_count,
          dpd_90_count, enquiries_6m, credit_vintage_yrs, avg_monthly_balance,
          bounce_count_6m, ltv, user, cibil_pdf_parsed)
    return result


def _save(result, age, emp, employer, tenure, cibil, income, itr, gst,
          dpd30, dpd60, dpd90, enq, vintage, amb, bounce, ltv, user, cibil_pdf_parsed):
    if not DATABASE_URL:
        return
    try:
        conn = get_db_conn()
        conn.run("""
            INSERT INTO loan_applications (
                application_id, applicant_name, age, employment_type, employer_name,
                loan_type, loan_amount, loan_tenure, cibil_score,
                dpd_30_count, dpd_60_count, dpd_90_count, enquiries_6m,
                credit_vintage_yrs, avg_monthly_balance, bounce_count_6m,
                monthly_income, itr_income, gst_turnover,
                decision, policy_violations, risk_level, risk_score,
                approved_amount, interest_rate, foir, ltv, emi_estimate,
                fraud_flags, regulatory_flags, strengths, concerns,
                documentation_required, reason, recommendation,
                counter_offer, bureau_assessment, cashflow_assessment,
                created_by, bank_name, cibil_pdf_parsed
            ) VALUES (
                :app_id, :name, :age, :emp, :employer,
                :lt, :la, :tenure, :cibil,
                :dpd30, :dpd60, :dpd90, :enq,
                :vintage, :amb, :bounce,
                :income, :itr, :gst,
                :decision, :pviol, :risk, :score,
                :approved, :rate, :foir, :ltv, :emi,
                :fraud, :reg, :strengths, :concerns,
                :docs, :reason, :rec, :counter, :bureau, :cashflow,
                :created_by, :bank_name, :cpdf
            )
        """,
            app_id=result["application_id"], name=result["applicant_name"],
            age=age, emp=emp, employer=employer,
            lt=result["loan_type"], la=result["loan_amount"],
            tenure=tenure, cibil=cibil,
            dpd30=dpd30, dpd60=dpd60, dpd90=dpd90, enq=enq,
            vintage=vintage, amb=amb, bounce=bounce,
            income=income, itr=itr, gst=gst,
            decision=result.get("decision"),
            pviol=json.dumps(result.get("policy_violations", [])),
            risk=result.get("risk_level"), score=result.get("risk_score"),
            approved=result.get("approved_amount", 0),
            rate=result.get("recommended_interest_rate"),
            foir=result.get("foir"), ltv=ltv, emi=result.get("emi_estimate"),
            fraud=json.dumps(result.get("fraud_flags", [])),
            reg=json.dumps(result.get("regulatory_flags", [])),
            strengths=json.dumps(result.get("strengths", [])),
            concerns=json.dumps(result.get("concerns", [])),
            docs=json.dumps(result.get("documentation_required", [])),
            reason=result.get("reason"), rec=result.get("recommendation"),
            counter=result.get("counter_offer"),
            bureau=result.get("bureau_assessment"),
            cashflow=result.get("cashflow_assessment"),
            created_by=user.get("username", "api"),
            bank_name=user.get("bank_name", ""),
            cpdf=cibil_pdf_parsed,
        )
        conn.close()
        logger.info(f"✅ Saved {result['application_id']} by {user.get('username')}")
    except Exception as e:
        logger.error(f"❌ DB save: {e}")


@app.get("/health")
def health():
    db_ok = False
    if DATABASE_URL:
        try:
            conn = get_db_conn(); conn.run("SELECT 1"); conn.close(); db_ok = True
        except Exception: pass
    return {
        "status": "ok",
        "service": "NBFC AI Platform v4.0",
        "loan_types": len(LOAN_RULES),
        "database": "connected" if db_ok else "not connected",
        "features": ["CIBIL PDF parsing", "Multi-user", "Multi-bank", "REST API", "Risk-based pricing"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
