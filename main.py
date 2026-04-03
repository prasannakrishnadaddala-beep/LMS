from fastapi import FastAPI, Request, Form, Response, Cookie, UploadFile, File, Header
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
import anthropic
import os, json, pg8000.native, ssl, base64, hashlib, secrets, string, random, logging, io
from urllib.parse import urlparse
try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False
    logger_pre = logging.getLogger(__name__)
    logger_pre.warning("pypdf not installed — password-protected PDFs will not be decryptable")
from datetime import datetime, timezone
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── PDF decryption helper ──────────────────────────────────────────────────────
def decrypt_pdf(content: bytes, password: str = "") -> bytes:
    """
    If the PDF is encrypted, decrypt it using pypdf and return clean bytes.
    If not encrypted, return original bytes.
    Raises ValueError with a clear, user-friendly message on every failure path.
    """
    if not PYPDF_AVAILABLE:
        return content  # pass as-is; Claude may still handle unencrypted PDFs

    try:
        reader = pypdf.PdfReader(io.BytesIO(content))
        if not reader.is_encrypted:
            return content  # nothing to do

        if not password:
            raise ValueError(
                "This PDF is password-protected. "
                "Please enter the password (usually your Date of Birth as DDMMYYYY, "
                "e.g. 01011990, or the last 4 digits of your account number)."
            )

        result = reader.decrypt(password)
        if result == pypdf.PasswordType.NOT_DECRYPTED:
            raise ValueError(
                "Incorrect password. Common formats: DOB as DDMMYYYY (e.g. 15081995), "
                "account number last 4 digits, or PAN number."
            )

        # Re-write without encryption so Claude can read it
        writer = pypdf.PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        out = io.BytesIO()
        writer.write(out)
        logger.info("PDF decrypted successfully (%d pages)", len(reader.pages))
        return out.getvalue()

    except ValueError:
        raise  # already user-friendly, re-raise as-is

    except ImportError:
        # cryptography package missing — should not happen if requirements.txt is correct
        raise ValueError(
            "Server configuration error: the cryptography package is missing. "
            "Please contact support or try uploading an unprotected version of the PDF."
        )

    except Exception as e:
        err_str = str(e).lower()
        # Catch the specific AES/cryptography missing error with a clear message
        if "cryptography" in err_str or "aes" in err_str:
            raise ValueError(
                "This PDF uses AES encryption. The server is missing a required package. "
                "Please contact support — or download an unprotected copy of your statement "
                "from your bank's portal and upload that instead."
            )
        if "password" in err_str:
            raise ValueError("Incorrect password. Please try again with your DOB (DDMMYYYY) or PAN.")
        logger.error("decrypt_pdf unexpected error: %s", e)
        raise ValueError(
            "Could not open this PDF. It may be corrupted or use an unsupported format. "
            "Try downloading a fresh copy from your bank portal."
        )

# ── Env vars ───────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set")

DATABASE_URL   = os.environ.get("DATABASE_URL", "")
SECRET_KEY     = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("⚠️  SECRET_KEY not set — sessions will be invalidated on every restart. Set SECRET_KEY in Railway env vars.")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")
if ADMIN_PASSWORD == "changeme123":
    logger.warning("⚠️  ADMIN_PASSWORD is still the default 'changeme123' — set ADMIN_PASSWORD in Railway env vars before going live.")

# ── PII masking for logs/audit (never log raw PAN/Aadhaar) ────────────────────
def mask_pan(pan: str) -> str:
    pan = (pan or "").strip()
    return pan[:5] + "****" + pan[-1] if len(pan) == 10 else pan[:3] + "****" if pan else ""

def mask_aadhaar(uid: str) -> str:
    digits = (uid or "").replace(" ", "")
    return f"XXXX XXXX {digits[-4:]}" if len(digits) >= 4 else "****"

# ── App setup ──────────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="NBFC AI Platform v5.0")
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

# ── Per-bank policy overrides ──────────────────────────────────────────────────
# Keys must match the bank_name stored in the users table exactly.
# Only fields listed here override the global LOAN_RULES; all others fall through.
# Add new banks or adjust thresholds without touching LOAN_RULES.
BANK_POLICIES: dict[str, dict[str, dict]] = {
    "HDFC Bank": {
        "Personal Loan":        {"min_cibil": 720, "max_foir": 45, "rate_range": [11, 22]},
        "Home Loan":            {"min_cibil": 680, "max_foir": 50},
        "Car Loan":             {"min_cibil": 700, "max_foir": 48},
        "Business Loan":        {"min_cibil": 700, "max_foir": 55, "rate_range": [13, 22]},
    },
    "ICICI Bank": {
        "Personal Loan":        {"min_cibil": 700, "max_foir": 50, "rate_range": [10.5, 22]},
        "Home Loan":            {"min_cibil": 650, "max_foir": 55},
        "Loan Against Property":{"min_cibil": 650, "max_foir": 55, "max_ltv": 70},
    },
    "Axis Bank": {
        "Personal Loan":        {"min_cibil": 700, "max_foir": 50},
        "Home Loan":            {"min_cibil": 650, "max_foir": 55},
    },
    "Bajaj Finance": {
        "Personal Loan":        {"min_cibil": 680, "max_foir": 55, "rate_range": [13, 26]},
        "Two-Wheeler Loan":     {"min_cibil": 600, "max_foir": 50, "max_ltv": 95},
        "Business Loan":        {"min_cibil": 675, "max_foir": 60, "rate_range": [15, 26]},
    },
    "Shriram Finance": {
        "Two-Wheeler Loan":     {"min_cibil": 0, "max_foir": 55, "max_ltv": 95, "rate_range": [14, 26]},
        "Car Loan":             {"min_cibil": 0, "max_foir": 55, "max_ltv": 90, "rate_range": [12, 22]},
        "Business Loan":        {"min_cibil": 650, "max_foir": 60, "rate_range": [16, 28]},
    },
    "Muthoot Finance": {
        "Gold Loan":            {"rate_range": [9, 16], "max_ltv": 75},
        "Personal Loan":        {"min_cibil": 700, "max_foir": 45, "rate_range": [14, 24]},
    },
    "Manappuram Finance": {
        "Gold Loan":            {"rate_range": [12, 26], "max_ltv": 75},
    },
}

def get_effective_rules(loan_type: str, bank_name: str) -> dict:
    """
    Merge global LOAN_RULES with any per-bank overrides for this (loan_type, bank_name) pair.
    Returns a new dict — never mutates LOAN_RULES.
    """
    base = LOAN_RULES.get(loan_type, {}).copy()
    overrides = BANK_POLICIES.get(bank_name, {}).get(loan_type, {})
    if overrides:
        base.update(overrides)
        logger.info(f"Bank policy applied: {bank_name} / {loan_type} → overrides={list(overrides.keys())}")
    return base

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
                employment_source      VARCHAR(20)   DEFAULT 'MANUAL',
                income_source          VARCHAR(20)   DEFAULT 'MANUAL',
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
                confidence_score       INTEGER       DEFAULT 0,
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
                redecision_hints       TEXT,
                bureau_assessment      TEXT,
                cashflow_assessment    TEXT,
                created_by             VARCHAR(50),
                bank_name              VARCHAR(100),
                cibil_pdf_parsed       BOOLEAN       DEFAULT FALSE,
                bank_stmt_parsed       BOOLEAN       DEFAULT FALSE,
                payslip_pdf_parsed     BOOLEAN       DEFAULT FALSE,
                created_at             TIMESTAMPTZ   DEFAULT NOW()
            )
        """)

        # Add new columns to existing tables (idempotent)
        for col_sql in [
            "ALTER TABLE loan_applications ADD COLUMN IF NOT EXISTS employment_source VARCHAR(20) DEFAULT 'MANUAL'",
            "ALTER TABLE loan_applications ADD COLUMN IF NOT EXISTS income_source VARCHAR(20) DEFAULT 'MANUAL'",
            "ALTER TABLE loan_applications ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 0",
            "ALTER TABLE loan_applications ADD COLUMN IF NOT EXISTS redecision_hints TEXT",
            "ALTER TABLE loan_applications ADD COLUMN IF NOT EXISTS bank_stmt_parsed BOOLEAN DEFAULT FALSE",
            "ALTER TABLE loan_applications ADD COLUMN IF NOT EXISTS payslip_pdf_parsed BOOLEAN DEFAULT FALSE",
        ]:
            try:
                _run_ddl(conn, col_sql)
            except Exception:
                pass  # Column may already exist

        # Audit log table — immutable record of every parse + decision
        _run_ddl(conn, """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id            SERIAL PRIMARY KEY,
                event_type    VARCHAR(50)  NOT NULL,
                application_id VARCHAR(30),
                username      VARCHAR(50),
                bank_name     VARCHAR(100),
                details       JSONB        DEFAULT '{}',
                ip_address    VARCHAR(45),
                created_at    TIMESTAMPTZ  DEFAULT NOW()
            )
        """)

        # Outcome feedback table — for learning system / model retraining
        _run_ddl(conn, """
            CREATE TABLE IF NOT EXISTS loan_outcomes (
                id             SERIAL PRIMARY KEY,
                application_id VARCHAR(30)  UNIQUE NOT NULL,
                outcome        VARCHAR(20)  NOT NULL,
                days_to_default INTEGER,
                reported_by    VARCHAR(50),
                reported_at    TIMESTAMPTZ  DEFAULT NOW(),
                notes          TEXT
            )
        """)


        # ── v5.0 Tables ───────────────────────────────────────────────────────
        _run_ddl(conn, """
            CREATE TABLE IF NOT EXISTS kyc_records (
                id             SERIAL PRIMARY KEY,
                application_id VARCHAR(30),
                kyc_type       VARCHAR(20)  NOT NULL,
                identifier     VARCHAR(20)  NOT NULL,
                name_on_kyc    VARCHAR(100),
                dob_on_kyc     VARCHAR(20),
                status         VARCHAR(20)  DEFAULT 'PENDING',
                match_score    INTEGER      DEFAULT 0,
                verified_by    VARCHAR(50),
                verified_at    TIMESTAMPTZ  DEFAULT NOW(),
                raw_response   JSONB        DEFAULT '{}'
            )
        """)
        _run_ddl(conn, """
            CREATE TABLE IF NOT EXISTS aml_screenings (
                id             SERIAL PRIMARY KEY,
                application_id VARCHAR(30),
                applicant_name VARCHAR(100),
                pan_masked     VARCHAR(20),
                risk_level     VARCHAR(20)  DEFAULT 'LOW',
                match_found    BOOLEAN      DEFAULT FALSE,
                match_details  TEXT,
                screened_by    VARCHAR(50),
                screened_at    TIMESTAMPTZ  DEFAULT NOW(),
                lists_checked  TEXT         DEFAULT '[]'
            )
        """)
        _run_ddl(conn, """
            CREATE TABLE IF NOT EXISTS colending_records (
                id             SERIAL PRIMARY KEY,
                application_id VARCHAR(30)  UNIQUE NOT NULL,
                partner_bank   VARCHAR(100),
                nbfc_share_pct NUMERIC(5,2) DEFAULT 20,
                bank_share_pct NUMERIC(5,2) DEFAULT 80,
                partner_rate   NUMERIC(5,2),
                blended_rate   NUMERIC(5,2),
                status         VARCHAR(20)  DEFAULT 'PROPOSED',
                created_by     VARCHAR(50),
                created_at     TIMESTAMPTZ  DEFAULT NOW()
            )
        """)
        _run_ddl(conn, """
            CREATE TABLE IF NOT EXISTS collections (
                id             SERIAL PRIMARY KEY,
                application_id VARCHAR(30)  NOT NULL,
                dpd_bucket     VARCHAR(20)  DEFAULT '0',
                outstanding    NUMERIC(15,2) DEFAULT 0,
                last_payment   NUMERIC(15,2) DEFAULT 0,
                last_payment_dt TIMESTAMPTZ,
                next_action    VARCHAR(100),
                agent_assigned VARCHAR(50),
                status         VARCHAR(20)  DEFAULT 'REGULAR',
                updated_by     VARCHAR(50),
                updated_at     TIMESTAMPTZ  DEFAULT NOW()
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

# ── Audit logger ──────────────────────────────────────────────────────────────
def write_audit_log(event_type: str, username: str, bank_name: str,
                    details: dict, application_id: str = None, ip: str = None):
    """Fire-and-forget audit log. Never raises — audit must not block requests."""
    if not DATABASE_URL:
        return
    try:
        conn = get_db_conn()
        conn.run(
            """INSERT INTO audit_logs (event_type, application_id, username, bank_name, details, ip_address)
               VALUES (:et, :aid, :u, :bn, :d::jsonb, :ip)""",
            et=event_type, aid=application_id, u=username, bn=bank_name,
            d=json.dumps(details), ip=ip
        )
        conn.close()
    except Exception as e:
        logger.warning(f"Audit log write failed (non-critical): {e}")

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


# ── Unified Document Parser — 1 AI call for all 3 doc types ──────────────────
@app.post("/parse-documents")
@limiter.limit("5/minute")
async def parse_documents(
    request:      Request,
    session:      str        = Cookie(default=None),
    cibil_file:   UploadFile = File(None),
    cibil_password: str      = Form(""),
    bank_file:    UploadFile = File(None),
    bank_password: str       = Form(""),
    payslip_file: UploadFile = File(None),
    payslip_password: str    = Form(""),
):
    """
    Parse up to 3 documents in a SINGLE Claude API call.
    Replaces 3x /parse-cibil + /parse-bank-statement + /parse-payslip calls.
    Uses Haiku (cheap + fast) for extraction.
    Returns: { cibil: {...}, bank: {...}, payslip: {...} } — null if not provided.
    """
    user = verify_session(session)
    if not user:
        return JSONResponse({"error": "Session expired. Please log in again."}, status_code=401)

    doc_blocks  = []   # Claude content blocks (text or document)
    doc_order   = []   # track which docs were sent and in what order

    # ── Helper: extract text from PDF bytes using pypdf ────────────────────────
    # Sending PDFs as raw base64 to Claude uses ~10x more tokens than plain text.
    # A 20MB bank statement PDF as base64 can exceed the 200k token limit alone.
    # We extract text first; only fall back to base64 if the PDF is image-only.
    def _pdf_to_text(pdf_bytes: bytes, label: str, max_chars: int = 60_000) -> str | None:
        """
        Extract text from a PDF using pypdf.
        Returns extracted text (truncated to max_chars) or None if the PDF
        appears to be scanned/image-only (no extractable text layer).
        """
        if not PYPDF_AVAILABLE:
            return None
        try:
            reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
            parts = []
            for i, page in enumerate(reader.pages):
                text = page.extract_text() or ""
                if text.strip():
                    parts.append(f"--- Page {i+1} ---\n{text}")
            full_text = "\n".join(parts).strip()
            if not full_text:
                logger.info("%s: no text layer found — will send as base64 PDF", label)
                return None
            if len(full_text) > max_chars:
                logger.info("%s: text truncated from %d to %d chars", label, len(full_text), max_chars)
                full_text = full_text[:max_chars] + "\n[... truncated for token limit ...]"
            logger.info("%s: extracted %d chars of text", label, len(full_text))
            return full_text
        except Exception as e:
            logger.warning("%s: text extraction failed (%s) — falling back to base64", label, e)
            return None

    def _make_block(pdf_bytes: bytes, label: str) -> dict:
        """
        Return the most token-efficient Claude content block for a PDF:
        - Text block if text can be extracted (typically 90% fewer tokens)
        - Base64 document block as fallback for scanned/image-only PDFs
        """
        text = _pdf_to_text(pdf_bytes, label)
        if text:
            return {"type": "text", "text": f"=== {label} DOCUMENT ===\n{text}"}
        # Fallback: base64 PDF (only for truly image-based PDFs)
        return {
            "type": "document",
            "source": {"type": "base64", "media_type": "application/pdf",
                       "data": base64.standard_b64encode(pdf_bytes).decode()}
        }

    async def _load(upload: UploadFile, password: str, max_mb: int, label: str):
        if not upload or not upload.filename:
            return None
        if not upload.filename.lower().endswith(".pdf"):
            raise ValueError(f"{label}: only PDF files are supported.")
        raw = await upload.read()
        if len(raw) > max_mb * 1024 * 1024:
            raise ValueError(f"{label}: file too large (max {max_mb} MB).")
        if len(raw) < 200:
            raise ValueError(f"{label}: file appears empty or corrupted.")
        try:
            return decrypt_pdf(raw, password.strip())
        except ValueError as e:
            # Prefix with doc label so the frontend can route the error
            # to the correct password input field
            raise ValueError(f"{label}: {e}") from e

    try:
        cibil_bytes   = await _load(cibil_file,   cibil_password,   15, "CIBIL report")
        bank_bytes    = await _load(bank_file,     bank_password,    20, "Bank statement")
        payslip_bytes = await _load(payslip_file,  payslip_password, 15, "Payslip")
    except ValueError as e:
        err_str = str(e)
        err_lower = err_str.lower()
        if err_lower.startswith("cibil"):
            doc_failed = "cibil"
        elif err_lower.startswith("bank"):
            doc_failed = "bank"
        elif err_lower.startswith("payslip"):
            doc_failed = "payslip"
        else:
            doc_failed = "unknown"
        return JSONResponse({"error": err_str, "doc_failed": doc_failed}, status_code=422)

    if not any([cibil_bytes, bank_bytes, payslip_bytes]):
        return JSONResponse({"error": "At least one document must be provided."}, status_code=400)

    # Build content blocks — text extraction first, base64 only as fallback
    if cibil_bytes:
        doc_blocks.append(_make_block(cibil_bytes, "CIBIL"))
        doc_order.append("CIBIL")

    if bank_bytes:
        doc_blocks.append(_make_block(bank_bytes, "BANK"))
        doc_order.append("BANK")

    if payslip_bytes:
        doc_blocks.append(_make_block(payslip_bytes, "PAYSLIP"))
        doc_order.append("PAYSLIP")

    # Build prompt dynamically based on which docs are present
    doc_instructions = []
    if "CIBIL" in doc_order:
        idx = doc_order.index("CIBIL") + 1
        doc_instructions.append(f"""
DOCUMENT {idx} IS THE CIBIL/BUREAU REPORT. Extract into "cibil" key:
{{"full_name":"","date_of_birth":"","age":null,"pan_number":"","mobile":"","email":"","address":"","gender":"",
"employer_name":"","monthly_income":0,"employment_type":"",
"cibil_score":null,"credit_vintage_yrs":0,"enquiries_6m":0,"dpd_30_count":0,"dpd_60_count":0,"dpd_90_count":0,
"writeoff_settled":"no","secured_unsecured_ratio":"","existing_emi_total":0,"total_active_loans":0,
"total_credit_cards":0,"credit_limit_total":0,"overdue_amount":0,"report_date":"","extraction_notes":""}}""")
    else:
        doc_instructions.append('"cibil": null')

    if "BANK" in doc_order:
        idx = doc_order.index("BANK") + 1
        doc_instructions.append(f"""
DOCUMENT {idx} IS THE BANK STATEMENT. Extract into "bank" key:
{{"account_holder":"","account_number":"","bank_name":"","account_type":"","statement_from":"","statement_to":"",
"avg_monthly_balance":0,"min_monthly_balance":0,"max_monthly_balance":0,
"avg_monthly_credit":0,"avg_monthly_debit":0,"bounce_count":0,
"salary_credits_count":0,"salary_amount":0,"salary_credit_regular":false,"emi_debits_detected":0,
"emi_accounts_count":0,"cash_withdrawals_monthly_avg":0,"upi_credits_monthly_avg":0,
"statement_months":0,"closing_balance":0,"inward_cheque_returns":0,"outward_cheque_returns":0,
"large_unusual_credits":0,"credit_debit_ratio":null,"extraction_notes":""}}""")
    else:
        doc_instructions.append('"bank": null')

    if "PAYSLIP" in doc_order:
        idx = doc_order.index("PAYSLIP") + 1
        doc_instructions.append(f"""
DOCUMENT {idx} IS THE PAYSLIP/SALARY SLIP. Extract into "payslip" key:
{{"employee_name":"","employee_id":"","employer_name":"","employer_pan":"","designation":"","department":"",
"employment_type":"","pay_period":"","gross_salary":0,"net_salary":0,"basic_salary":0,"hra":0,
"special_allowance":0,"pf_deduction":0,"tds_deduction":0,"professional_tax":0,"total_deductions":0,
"uan_number":"","pan_number":"","bank_account_last4":"","months_count":1,"extraction_notes":""}}""")
    else:
        doc_instructions.append('"payslip": null')

    prompt = f"""You are an expert Indian lending document extraction system.
You have been given {len(doc_order)} document(s): {", ".join(doc_order)}.
Extract data from each document carefully. Return ONLY valid JSON — no explanation, no markdown:

{{
{chr(10).join(doc_instructions)}
}}

Rules:
- Default numeric fields to 0, string fields to "", boolean fields to false
- For missing/unreadable documents, use null for the entire key
- pan_number and uan_number: show masked versions if partially visible
- employment_type must be one of: "Salaried — Private Sector" | "Salaried — Government / PSU" | "Self-Employed Professional" | "Business Owner / Proprietor" | "Freelancer / Consultant" | ""
"""

    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=3000,
            messages=[{"role": "user", "content": doc_blocks + [{"type": "text", "text": prompt}]}]
        )
        raw    = message.content[0].text.strip().replace("```json","").replace("```","").strip()
        result = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error(f"parse-documents JSON error: {e}")
        return JSONResponse({"error": "Could not parse AI response. Please try again."}, status_code=422)
    except Exception as e:
        logger.error(f"parse-documents Claude error: {e}")
        return JSONResponse({"error": f"Document parsing failed: {e}"}, status_code=500)

    # Audit log
    write_audit_log("BULK_DOC_PARSE", user["username"], user.get("bank_name",""),
                    {"docs_parsed": doc_order, "cibil_score": (result.get("cibil") or {}).get("cibil_score"),
                     "net_salary": (result.get("payslip") or {}).get("net_salary")})

    logger.info(f"Bulk parse by {user['username']}: {doc_order} in 1 API call")
    return JSONResponse({"ok": True, "docs_parsed": doc_order, "data": result})

# ── CIBIL PDF Parser ───────────────────────────────────────────────────────────
@app.post("/parse-cibil")
@limiter.limit("5/minute")
async def parse_cibil(
    request: Request,
    session: str  = Cookie(default=None),
    file: UploadFile = File(...),
    pdf_password: str = Form(""),
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
    if len(content) < 500:
        return JSONResponse({"error": "PDF appears to be empty or corrupted."}, status_code=400)

    # Decrypt if password-protected
    try:
        content = decrypt_pdf(content, pdf_password.strip())
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=422)

    b64 = base64.standard_b64encode(content).decode("utf-8")

    extraction_prompt = """You are an expert CIBIL/credit bureau data extraction system for Indian lenders.
Carefully read this credit report and extract every available data point including personal details and employment information.

Return ONLY valid JSON — no explanation, no markdown, no preamble:
{
  "full_name": <full applicant name exactly as printed on the report, or "">,
  "date_of_birth": <DOB in DD/MM/YYYY or YYYY-MM-DD format, or "">,
  "age": <integer age calculated from DOB if available, else null>,
  "pan_number": <PAN number (masked or full) if visible, e.g. "ABCDE1234F" or "ABCDE****F", or "">,
  "mobile": <mobile number if visible on report, or "">,
  "email": <email address if visible, or "">,
  "address": <current or permanent address from report, condensed to one line, or "">,
  "gender": <"Male" or "Female" or "">,

  "employer_name": <current employer name as listed under Employment section of the report, or "">,
  "monthly_income": <monthly income in rupees if shown under Employment/Income section, else 0>,
  "employment_type": <infer from employer details — one of: "Salaried — Private Sector" | "Salaried — Government / PSU" | "Self-Employed Professional" | "Business Owner / Proprietor" | "Freelancer / Consultant" | "" — use "Salaried — Government / PSU" if employer is a govt body/PSU/bank, "Salaried — Private Sector" for private companies>,

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
  "report_date": <report generation date as string, or "">,
  "extraction_notes": <string, max 200 chars, important observations e.g. "3 active personal loans", "guarantor accounts present", "CRIF report">
}"""

    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1400,
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
        pan_safe = mask_pan(result.get("pan_number", ""))
        logger.info(f"CIBIL parsed by {user['username']}: score={result.get('cibil_score')} pan={pan_safe}")
        write_audit_log("CIBIL_PARSE", user["username"], user.get("bank_name",""),
                        {"score": result.get("cibil_score"), "pan_masked": pan_safe,
                         "name": result.get("full_name","")})
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
    pdf_password: str = Form(""),
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

    # Decrypt if password-protected
    try:
        content = decrypt_pdf(content, pdf_password.strip())
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=422)

    b64 = base64.standard_b64encode(content).decode("utf-8")

    extraction_prompt = """You are an expert Indian bank statement analysis system for NBFC credit underwriting.
Analyze this bank statement carefully and extract all financial signals and account holder details.

Return ONLY valid JSON — no explanation, no markdown, no preamble:
{
  "account_holder": <full name of account holder exactly as printed, or "">,
  "account_number": <account number, last 4 digits only if full not visible, or "">,
  "bank_name": <bank name as appearing on statement, or "">,
  "branch": <branch name/address, or "">,
  "ifsc_code": <IFSC code if visible, or "">,
  "account_type": <"Savings" or "Current" or "OD" or "">,
  "statement_from": <start date of statement in DD/MM/YYYY, or "">,
  "statement_to": <end date of statement in DD/MM/YYYY, or "">,

  "avg_monthly_balance": <average end-of-day balance over all months, in rupees, default 0>,
  "min_monthly_balance": <lowest monthly closing balance seen, in rupees, default 0>,
  "max_monthly_balance": <highest monthly closing balance seen, in rupees, default 0>,
  "avg_monthly_credit": <average total credits (inflows) per month in rupees, default 0>,
  "avg_monthly_debit": <average total debits (outflows) per month in rupees, default 0>,
  "bounce_count": <total number of bounced/returned cheques or ECS/NACH returns, default 0>,
  "salary_credits_count": <number of months with regular salary credit detected, default 0>,
  "salary_amount": <detected monthly salary credit amount if consistent, else 0>,
  "salary_credit_regular": <true if salary credited on similar dates each month, else false>,
  "emi_debits_detected": <estimated total monthly EMI/loan debit outflows in rupees, default 0>,
  "emi_accounts_count": <number of distinct loan EMI debits detected, default 0>,
  "cash_withdrawals_monthly_avg": <average monthly cash withdrawal amount, default 0>,
  "upi_credits_monthly_avg": <average monthly UPI/NEFT inflow from business/clients, default 0>,
  "statement_months": <number of months covered by this statement, default 0>,
  "closing_balance": <most recent closing balance in the statement, default 0>,
  "inward_cheque_returns": <number of inward cheque/ECS returns, default 0>,
  "outward_cheque_returns": <number of outward cheque/ECS/NACH returns — payment defaults, default 0>,
  "large_unusual_credits": <number of unusually large one-time credits not matching salary pattern, default 0>,
  "credit_debit_ratio": <round(avg_monthly_credit / avg_monthly_debit, 2) if debit > 0 else null>,
  "extraction_notes": <string max 200 chars — key observations like "GST credits visible", "2 loan EMIs detected", "irregular salary">
}"""

    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
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
        logger.info(f"Bank statement parsed by {user['username']}: holder={result.get('account_holder','')} AMB=₹{result.get('avg_monthly_balance')}")
        write_audit_log("BANK_STMT_PARSE", user["username"], user.get("bank_name",""),
                        {"amb": result.get("avg_monthly_balance"), "months": result.get("statement_months"),
                         "bounces": result.get("bounce_count"), "bank": result.get("bank_name","")})
        return JSONResponse(content={"ok": True, "data": result})
    except json.JSONDecodeError as e:
        logger.error(f"Bank statement JSON parse error: {e}")
        return JSONResponse({"error": "Could not extract structured data. Ensure this is a valid bank statement PDF."}, status_code=422)
    except Exception as e:
        logger.error(f"Bank statement parse exception: {e}")
        return JSONResponse({"error": "PDF parsing failed. Please try again."}, status_code=500)


# ── Payslip PDF Parser ──────────────────────────────────────────────────────────
@app.post("/parse-payslip")
@limiter.limit("5/minute")
async def parse_payslip_endpoint(
    request: Request,
    session: str  = Cookie(default=None),
    file: UploadFile = File(...),
    pdf_password: str = Form(""),
):
    user = verify_session(session)
    if not user:
        return JSONResponse({"error": "Session expired. Please log in again."}, status_code=401)

    fname = (file.filename or "").lower()
    if not fname.endswith(".pdf"):
        return JSONResponse({"error": "Please upload a payslip PDF file."}, status_code=400)

    content = await file.read()
    if len(content) > 15 * 1024 * 1024:
        return JSONResponse({"error": "PDF too large. Maximum size is 15 MB."}, status_code=400)
    if len(content) < 200:
        return JSONResponse({"error": "PDF appears to be empty or corrupted."}, status_code=400)

    try:
        content = decrypt_pdf(content, pdf_password.strip())
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=422)

    b64 = base64.standard_b64encode(content).decode("utf-8")

    extraction_prompt = """You are an expert Indian payslip / salary slip analysis system for NBFC credit underwriting.
Carefully parse this payslip or salary slip and extract all available data points.
This is the MOST AUTHORITATIVE source for employment and income verification.

Return ONLY valid JSON — no explanation, no markdown, no preamble:
{
  "employee_name": <full name exactly as printed on payslip, or "">,
  "employee_id": <employee ID/code if visible, or "">,
  "employer_name": <company/employer name exactly as printed (usually at top of payslip), or "">,
  "employer_pan": <employer PAN if visible, or "">,
  "designation": <job title/role/designation, or "">,
  "department": <department/division if visible, or "">,
  "employment_type": <infer — one of: "Salaried — Private Sector" | "Salaried — Government / PSU" | "Self-Employed Professional" | ""  — use Govt/PSU if payslip is from government/PSU/defence/railway/bank>,
  "pay_period": <month and year e.g. "March 2025", or "">,
  "gross_salary": <gross monthly salary in rupees (before deductions), default 0>,
  "net_salary": <net take-home salary in rupees (after all deductions), this is MOST IMPORTANT — default 0>,
  "basic_salary": <basic salary component in rupees, default 0>,
  "hra": <House Rent Allowance in rupees, default 0>,
  "special_allowance": <special/other allowances combined, default 0>,
  "pf_deduction": <PF/EPF employee contribution in rupees, default 0>,
  "tds_deduction": <TDS/income tax deduction in rupees, default 0>,
  "professional_tax": <professional tax, default 0>,
  "total_deductions": <total of all deductions, default 0>,
  "uan_number": <UAN/PF account number if visible, or "">,
  "pan_number": <employee PAN if visible (may be masked), or "">,
  "bank_account_last4": <last 4 digits of salary bank account if visible, or "">,
  "months_count": <number of payslips if multiple months uploaded, default 1>,
  "extraction_notes": <string max 200 chars — key observations like "Government payslip", "Multiple months", "CTC breakdown visible", "Contractual employee">
}"""

    try:
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
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
        pan_safe = mask_pan(result.get("pan_number", ""))
        logger.info(f"Payslip parsed by {user['username']}: employer={result.get('employer_name','')} net=₹{result.get('net_salary')} pan={pan_safe}")
        write_audit_log("PAYSLIP_PARSE", user["username"], user.get("bank_name",""),
                        {"employer": result.get("employer_name",""), "net_salary": result.get("net_salary"),
                         "pan_masked": pan_safe, "designation": result.get("designation","")})
        return JSONResponse(content={"ok": True, "data": result})
    except json.JSONDecodeError as e:
        logger.error(f"Payslip JSON parse error: {e}")
        return JSONResponse({"error": "Could not extract structured data from this payslip. Ensure it is a valid salary slip PDF."}, status_code=422)
    except Exception as e:
        logger.error(f"Payslip parse exception: {e}")
        return JSONResponse({"error": "PDF parsing failed. Please try again."}, status_code=500)


# ── Document Source Priority Engine ───────────────────────────────────────────
def resolve_employment_source(body: dict) -> dict:
    """
    Priority: Payslip (authoritative) > Bank Statement (inferred) > CIBIL (inferential) > Manual
    """
    ps_parsed    = bool(body.get("payslip_pdf_parsed", False))
    bs_parsed    = bool(body.get("bank_statement_parsed", False))
    cibil_parsed = bool(body.get("cibil_pdf_parsed", False))

    # Priority 1: Payslip — most authoritative (actual employer document)
    if ps_parsed and body.get("ps_employer_name", "").strip():
        emp_type = body.get("ps_employment_type") or body.get("employment_type", "")
        return {
            "employment_type": emp_type,
            "employer_name":   body.get("ps_employer_name", ""),
            "source":          "PAYSLIP",
            "source_label":    "✅ Verified from Payslip",
            "is_verified":     True,
        }

    # Priority 2: Bank statement — salary credits confirm salaried status
    if bs_parsed and float(body.get("bs_salary_amount", 0)) > 0:
        return {
            "employment_type": body.get("employment_type") or "Salaried — Private Sector",
            "employer_name":   body.get("employer_name", ""),
            "source":          "BANK",
            "source_label":    "✅ Salary Pattern Verified via Bank Statement",
            "is_verified":     True,
        }

    # Priority 3: CIBIL — inferential only (credit accounts, not employer contract)
    if cibil_parsed:
        return {
            "employment_type": body.get("employment_type", ""),
            "employer_name":   body.get("employer_name", ""),
            "source":          "CIBIL",
            "source_label":    "⚠️ Employment inferred from CIBIL (unverified — payslip recommended)",
            "is_verified":     False,
        }

    # Manual entry
    return {
        "employment_type": body.get("employment_type", ""),
        "employer_name":   body.get("employer_name", ""),
        "source":          "MANUAL",
        "source_label":    "📝 Manually entered — not document-verified",
        "is_verified":     False,
    }


def resolve_income_source(body: dict) -> dict:
    """
    Priority: Payslip net salary > Bank salary credits > ITR/12 > Manual declared
    """
    ps_net    = float(body.get("ps_net_salary", 0))
    bs_salary = float(body.get("bs_salary_amount", 0))
    declared  = float(body.get("monthly_income", 0))
    itr_ann   = float(body.get("itr_income", 0))

    if bool(body.get("payslip_pdf_parsed")) and ps_net > 0:
        return {
            "monthly_income":  ps_net,
            "gross_salary":    float(body.get("ps_gross_salary", ps_net)),
            "source":          "PAYSLIP",
            "declared":        declared,
            "variance_pct":    round(abs(ps_net - declared) / declared * 100, 1) if declared > 0 else 0,
        }

    if bool(body.get("bank_statement_parsed")) and bs_salary > 0:
        return {
            "monthly_income":  bs_salary,
            "gross_salary":    bs_salary,
            "source":          "BANK",
            "declared":        declared,
            "variance_pct":    round(abs(bs_salary - declared) / declared * 100, 1) if declared > 0 else 0,
        }

    if itr_ann > 0:
        itr_monthly = round(itr_ann / 12)
        return {
            "monthly_income":  declared,   # use declared but flag ITR
            "gross_salary":    declared,
            "source":          "ITR",
            "declared":        declared,
            "itr_monthly":     itr_monthly,
            "variance_pct":    round(abs(itr_monthly - declared) / declared * 100, 1) if declared > 0 else 0,
        }

    return {
        "monthly_income":  declared,
        "gross_salary":    declared,
        "source":          "MANUAL",
        "declared":        declared,
        "variance_pct":    0,
    }


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


# ── Deterministic Confidence Score Engine ─────────────────────────────────────
def compute_confidence(cibil_pdf: bool, bank_parsed: bool, payslip_parsed: bool,
                       income_source: str, emp_source: str) -> int:
    """
    Rule-based confidence score — used as a floor/override for the AI-assigned score.
    More documents verified = higher confidence. Never fully delegated to the LLM.

    Scoring:
      Base (manual-only)    = 40
      + Payslip verified    = +30  (highest: authoritative employer + income proof)
      + Bank stmt verified  = +15  (secondary: cash-flow confirmation)
      + CIBIL PDF verified  = +10  (tertiary: bureau data quality)
      + Payslip income src  = +5   (income from most reliable source)
      + Bank income src     = +3
    Max = 100
    """
    score = 40
    if payslip_parsed:
        score += 30
    if bank_parsed:
        score += 15
    if cibil_pdf:
        score += 10
    if income_source == "PAYSLIP":
        score += 5
    elif income_source == "BANK":
        score += 3
    return min(score, 100)


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
    # Bank statement hidden fields (populated by JS after parse)
    bank_statement_parsed:       str   = Form("no"),
    bs_salary_amount:            float = Form(0),
    bs_avg_monthly_balance:      float = Form(0),
    bs_bounce_count:             int   = Form(0),
    bs_emi_debits_detected:      float = Form(0),
    bs_large_unusual_credits:    int   = Form(0),
    bs_credit_debit_ratio:       float = Form(0),
    bs_statement_months:         int   = Form(0),
    bs_upi_credits_monthly_avg:  float = Form(0),
    bs_emi_accounts_count:       int   = Form(0),
    # Payslip fields
    payslip_pdf_parsed:   str   = Form("no"),
    ps_employer_name:     str   = Form(""),
    ps_employment_type:   str   = Form(""),
    ps_net_salary:        float = Form(0),
    ps_gross_salary:      float = Form(0),
    ps_employee_name:     str   = Form(""),
    ps_designation:       str   = Form(""),
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
        # Bank statement fields — previously dropped, now correctly forwarded
        "bank_statement_parsed":    bank_statement_parsed.lower() in ("yes","true","1"),
        "bs_salary_amount":         bs_salary_amount,
        "bs_avg_monthly_balance":   bs_avg_monthly_balance,
        "bs_bounce_count":          bs_bounce_count,
        "bs_emi_debits_detected":   bs_emi_debits_detected,
        "bs_large_unusual_credits": bs_large_unusual_credits,
        "bs_credit_debit_ratio":    bs_credit_debit_ratio,
        "bs_statement_months":      bs_statement_months,
        "bs_upi_credits_monthly_avg": bs_upi_credits_monthly_avg,
        "bs_emi_accounts_count":    bs_emi_accounts_count,
        "payslip_pdf_parsed": payslip_pdf_parsed.lower() in ("yes","true","1"),
        "ps_employer_name": ps_employer_name.strip()[:100],
        "ps_employment_type": ps_employment_type,
        "ps_net_salary": ps_net_salary,
        "ps_gross_salary": ps_gross_salary,
        "ps_employee_name": ps_employee_name.strip()[:100],
        "ps_designation": ps_designation.strip()[:100],
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
    payslip_pdf_parsed  = bool(body.get("payslip_pdf_parsed", False))
    bs_salary_amount    = float(body.get("bs_salary_amount", 0))
    bs_avg_balance      = float(body.get("bs_avg_monthly_balance", 0))
    bs_bounce_count     = int(body.get("bs_bounce_count", 0))
    bs_emi_debits       = float(body.get("bs_emi_debits_detected", 0))
    bs_large_credits    = int(body.get("bs_large_unusual_credits", 0))
    bs_cd_ratio         = float(body.get("bs_credit_debit_ratio", 0) or 0)
    bs_stmt_months      = int(body.get("bs_statement_months", 0))
    bs_upi_credits      = float(body.get("bs_upi_credits_monthly_avg", 0))
    # Payslip fields
    ps_employer_name    = str(body.get("ps_employer_name", "")).strip()
    ps_employment_type  = str(body.get("ps_employment_type", "")).strip()
    ps_net_salary       = float(body.get("ps_net_salary", 0))
    ps_gross_salary     = float(body.get("ps_gross_salary", 0))
    ps_employee_name    = str(body.get("ps_employee_name", "")).strip()
    ps_designation      = str(body.get("ps_designation", "")).strip()

    # ── Document Source Priority Engine ───────────────────────────────────────
    emp_resolved    = resolve_employment_source(body)
    income_resolved = resolve_income_source(body)

    # Override employment_type and employer_name with priority-resolved values
    employment_type = emp_resolved["employment_type"] or employment_type
    employer_name   = emp_resolved["employer_name"]   or employer_name
    emp_source      = emp_resolved["source"]
    emp_source_lbl  = emp_resolved["source_label"]

    # Override monthly_income with priority-resolved value (payslip net salary wins)
    verified_income = income_resolved["monthly_income"]
    income_source   = income_resolved["source"]
    income_variance = income_resolved.get("variance_pct", 0)

    # Use verified income for FOIR calculation (more accurate)
    if income_resolved["source"] in ("PAYSLIP", "BANK") and verified_income > 0:
        monthly_income = verified_income

    # Bank statement overrides manual inputs when available (but NOT over payslip)
    if bank_stmt_parsed:
        if bs_avg_balance > 0:
            avg_monthly_balance = bs_avg_balance
        if bs_bounce_count > bounce_count_6m:
            bounce_count_6m = bs_bounce_count
        if bs_emi_debits > existing_emi_total:
            existing_emi_total = bs_emi_debits

    if loan_type not in LOAN_RULES:
        return {"error": "Invalid loan type."}

    rules = get_effective_rules(loan_type, user.get("bank_name", ""))

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
              bounce_count_6m, ltv, user, cibil_pdf_parsed,
              bank_stmt_parsed, payslip_pdf_parsed, emp_source, income_source)
        return result

    btr = "N/A"
    if gst_turnover > 0 and avg_monthly_balance > 0:
        btr = f"{round((avg_monthly_balance * 12) / gst_turnover * 100, 1)}%"

    bureau_source = "CIBIL report PDF (auto-extracted)" if cibil_pdf_parsed else "manually entered"
    bs_source     = "Bank statement PDF (auto-extracted)" if bank_stmt_parsed else "manually entered"

    # Payslip section for AI prompt
    payslip_section = ""
    if payslip_pdf_parsed and ps_net_salary > 0:
        income_match = ""
        if monthly_expenses > 0:
            diff_pct = abs(ps_net_salary - income_resolved["declared"]) / max(income_resolved["declared"], 1) * 100
            income_match = f"[MATCHES DECLARED ✅]" if diff_pct < 15 else f"[MISMATCH with declared ₹{income_resolved['declared']:,.0f} — {diff_pct:.0f}% difference ⚠️]"
        payslip_section = f"""
PAYSLIP VERIFICATION (HIGHEST PRIORITY — authoritative employer/income proof):
- Employer (from payslip): {ps_employer_name or 'Extracted'} | Designation: {ps_designation or 'N/A'}
- Employment type (payslip): {ps_employment_type or employment_type}
- Net take-home salary: ₹{ps_net_salary:,.0f}/mo {income_match}
- Gross salary: ₹{ps_gross_salary:,.0f}/mo
- Employee name on payslip: {ps_employee_name or 'N/A'}
⚡ USE PAYSLIP as primary source for employer and income — override CIBIL inferences."""

    # Income source summary for prompt
    income_source_note = {
        "PAYSLIP": f"₹{verified_income:,.0f}/mo [SOURCE: PAYSLIP ✅ highest reliability]",
        "BANK":    f"₹{verified_income:,.0f}/mo [SOURCE: Bank statement credits ✅]",
        "ITR":     f"₹{monthly_income:,.0f}/mo declared [ITR annualised: ₹{income_resolved.get('itr_monthly',0):,.0f}/mo]",
        "MANUAL":  f"₹{monthly_income:,.0f}/mo [SOURCE: Manual entry — unverified]",
    }.get(income_source, f"₹{monthly_income:,.0f}/mo")

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

⚡ DOCUMENT PRIORITY RULES (follow strictly):
1. Payslip = HIGHEST authority for employment type, employer name, and income
2. Bank statement = SECONDARY authority (salary credits, cash flow patterns)
3. CIBIL = TERTIARY (credit history only — NOT authoritative for employment/income)
4. Manual entry = LOWEST priority — treat as unverified unless supported by documents

Employment source: {emp_source_lbl}
Income source: {income_source}
Bureau data: {bureau_source}
{payslip_section}
LOAN: {loan_type} | Rate range: {rules['rate_range'][0]}%-{rules['rate_range'][1]}% | Risk-computed rate: {computed_rate}%
Policy: Max FOIR {rules['max_foir']}% | Min CIBIL {rules['min_cibil'] if rules['min_cibil'] > 0 else 'N/A'} | Max LTV {max_ltv}% | Max Tenure {rules['max_tenure']}m | Priority Sector: {'YES' if rules['priority_sector'] else 'NO'}
Underwriting note: {rules['key_check']}

APPLICANT: {full_name}, Age {age}, {employment_type}
Employer: {employer_name or 'Not specified'} | Designation: {ps_designation or 'N/A'} | Employer vintage: {employer_vintage_yrs}y | Business vintage: {business_vintage_yrs}y {'[BELOW 2yr min for BL]' if loan_type == 'Business Loan' and business_vintage_yrs < 2 else ''}

INCOME & CASHFLOW (source-verified):
- Income: {income_source_note}
- Declared monthly income: ₹{income_resolved['declared']:,.0f} | Expenses: ₹{monthly_expenses:,.0f} | Net disposable: ₹{net_income:,.0f}
- ITR income (annual): ₹{itr_income:,.0f} {('[INCOME GAP: ' + income_gap + ']') if income_gap else ''}
- GST turnover (annual): ₹{gst_turnover:,.0f} | Banking turnover ratio: {btr}
- Avg monthly bank balance: ₹{avg_monthly_balance:,.0f}{'  [from bank statement ✅]' if bank_stmt_parsed else ''}
- Salary/credit regularity: {'Regular' if sal_reg_bool else 'IRREGULAR'}
- Cheque/ECS bounces (6m): {bounce_count_6m} {'[CAUTION]' if bounce_count_6m > 1 else ''}
{bs_section}
BUREAU ({bureau_source}):
- CIBIL: {cibil_score} | Credit vintage: {credit_vintage_yrs}y | Secured/unsecured mix: {secured_unsecured_ratio or 'N/A'}
- DPD 30+: {dpd_30_count} | DPD 60+: {dpd_60_count} | DPD 90+: {dpd_90_count}
- Write-off/settlement: {'YES' if wo_bool else 'None'} | Enquiries (6m): {enquiries_6m} {'[HIGH]' if enquiries_6m > 3 else ''}
- Existing EMI obligations: ₹{existing_emi_total:,.0f}/month{'  [detected from bank statement ✅]' if bank_stmt_parsed and bs_emi_debits > 0 else ''}

LOAN REQUEST:
- Amount: ₹{loan_amount:,.0f} | Tenure: {loan_tenure}m | Purpose: {loan_purpose}
- EMI estimate: ₹{emi:,.0f} | FOIR post-EMI: {foir}% {'[EXCEEDS LIMIT]' if foir > rules['max_foir'] else '[OK]'}
- Collateral: ₹{collateral_value:,.0f} | LTV: {str(ltv)+'%' if ltv else 'N/A'} {'[LTV BREACH]' if ltv_breach else ''}
- Documents verified: {'Payslip ✅' if payslip_pdf_parsed else ''} {'Bank Stmt ✅' if bank_stmt_parsed else ''} {'CIBIL PDF ✅' if cibil_pdf_parsed else ''}
{fraud_section}
Respond ONLY with this JSON (no other text):
{{
  "decision": "APPROVED" or "REJECTED" or "CONDITIONAL",
  "risk_level": "LOW" or "MEDIUM" or "HIGH",
  "risk_score": <0-100>,
  "confidence_score": <0-100, higher when more documents verified — payslip+bank+cibil = 95+, only manual = 40-60>,
  "approved_amount": <number or 0>,
  "recommended_interest_rate": {computed_rate},
  "processing_fee": <rupee amount>,
  "max_eligible_tenure": <months>,
  "fraud_flags": {json.dumps(pre_fraud_flags)},
  "regulatory_flags": [],
  "bureau_assessment": "<2-3 sentences on bureau quality>",
  "cashflow_assessment": "<2-3 sentences on income, banking, FOIR — mention document sources explicitly>",
  "strengths": ["s1","s2","s3"],
  "concerns": ["c1","c2"],
  "policy_violations": [],
  "reason": "<3-4 plain English sentences — explicitly mention which documents were used and their reliability>",
  "recommendation": "<specific action for credit committee — mention document source quality>",
  "counter_offer": "<if REJECTED: what amount/tenure/conditions would work, or null>",
  "redecision_hints": "<if REJECTED: 2-3 specific actions applicant can take to qualify e.g. 'Upload 3 payslips', 'Reduce EMI by closing X loan', 'Add co-applicant', or null if approved>",
  "documentation_required": {json.dumps(rules['docs'])}
}}"""

    try:
        message = client.messages.create(
            model="claude-sonnet-4-6",
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

    # Deterministic confidence score — use as floor; never let Claude return lower
    # than what the document evidence warrants.
    rule_based_confidence = compute_confidence(
        cibil_pdf=cibil_pdf_parsed,
        bank_parsed=bank_stmt_parsed,
        payslip_parsed=payslip_pdf_parsed,
        income_source=income_source,
        emp_source=emp_source,
    )
    ai_confidence = int(result.get("confidence_score") or 0)
    final_confidence = max(rule_based_confidence, ai_confidence)

    result.update({
        "application_id": app_id, "loan_type": loan_type,
        "applicant_name": full_name, "loan_amount": loan_amount,
        "emi_estimate": round(emi), "foir": foir,
        "ltv": ltv, "computed_rate": computed_rate, "policy_violations": [],
        "cibil_pdf_parsed": cibil_pdf_parsed,
        "bank_statement_parsed": bank_stmt_parsed,
        "payslip_pdf_parsed": payslip_pdf_parsed,
        "employment_source": emp_source,
        "income_source": income_source,
        "confidence_score": final_confidence,
        "fraud_flags": result.get("fraud_flags", pre_fraud_flags),
        "redecision_hints": result.get("redecision_hints"),
    })
    _save(result, age, employment_type, employer_name, loan_tenure, cibil_score,
          monthly_income, itr_income, gst_turnover, dpd_30_count, dpd_60_count,
          dpd_90_count, enquiries_6m, credit_vintage_yrs, avg_monthly_balance,
          bounce_count_6m, ltv, user, cibil_pdf_parsed,
          bank_stmt_parsed, payslip_pdf_parsed, emp_source, income_source)
    return result


def _save(result, age, emp, employer, tenure, cibil, income, itr, gst,
          dpd30, dpd60, dpd90, enq, vintage, amb, bounce, ltv, user,
          cibil_pdf_parsed, bank_stmt_parsed=False, payslip_pdf_parsed=False,
          emp_source="MANUAL", income_source="MANUAL"):
    if not DATABASE_URL:
        return
    try:
        conn = get_db_conn()
        conn.run("""
            INSERT INTO loan_applications (
                application_id, applicant_name, age, employment_type, employer_name,
                employment_source, income_source,
                loan_type, loan_amount, loan_tenure, cibil_score,
                dpd_30_count, dpd_60_count, dpd_90_count, enquiries_6m,
                credit_vintage_yrs, avg_monthly_balance, bounce_count_6m,
                monthly_income, itr_income, gst_turnover,
                decision, policy_violations, risk_level, risk_score, confidence_score,
                approved_amount, interest_rate, foir, ltv, emi_estimate,
                fraud_flags, regulatory_flags, strengths, concerns,
                documentation_required, reason, recommendation,
                counter_offer, redecision_hints, bureau_assessment, cashflow_assessment,
                created_by, bank_name, cibil_pdf_parsed, bank_stmt_parsed, payslip_pdf_parsed
            ) VALUES (
                :app_id, :name, :age, :emp, :employer,
                :emp_source, :income_source,
                :lt, :la, :tenure, :cibil,
                :dpd30, :dpd60, :dpd90, :enq,
                :vintage, :amb, :bounce,
                :income, :itr, :gst,
                :decision, :pviol, :risk, :score, :confidence,
                :approved, :rate, :foir, :ltv, :emi,
                :fraud, :reg, :strengths, :concerns,
                :docs, :reason, :rec, :counter, :redecision, :bureau, :cashflow,
                :created_by, :bank_name, :cpdf, :bspdf, :pspdf
            )
        """,
            app_id=result["application_id"], name=result["applicant_name"],
            age=age, emp=emp, employer=employer,
            emp_source=emp_source, income_source=income_source,
            lt=result["loan_type"], la=result["loan_amount"],
            tenure=tenure, cibil=cibil,
            dpd30=dpd30, dpd60=dpd60, dpd90=dpd90, enq=enq,
            vintage=vintage, amb=amb, bounce=bounce,
            income=income, itr=itr, gst=gst,
            decision=result.get("decision"),
            pviol=json.dumps(result.get("policy_violations", [])),
            risk=result.get("risk_level"), score=result.get("risk_score"),
            confidence=result.get("confidence_score", 0),
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
            redecision=result.get("redecision_hints"),
            bureau=result.get("bureau_assessment"),
            cashflow=result.get("cashflow_assessment"),
            created_by=user.get("username", "api"),
            bank_name=user.get("bank_name", ""),
            cpdf=cibil_pdf_parsed,
            bspdf=bank_stmt_parsed,
            pspdf=payslip_pdf_parsed,
        )
        conn.close()
        logger.info(f"✅ Saved {result['application_id']} by {user.get('username')} [emp_src={emp_source} inc_src={income_source}]")
    except Exception as e:
        logger.error(f"❌ DB save: {e}")



# ── Outcome Feedback API (Learning System Foundation) ─────────────────────────
@app.post("/api/v1/feedback")
@limiter.limit("30/minute")
async def submit_outcome(request: Request, x_api_key: str = Header(default="")):
    """
    Let lenders submit actual loan outcomes back to the platform.
    This is the data foundation for a future ML risk model.

    Body: {
        "application_id": "LN-20260403-XXXXX",
        "outcome": "repaid" | "defaulted" | "prepaid" | "npa" | "restructured",
        "days_to_default": 90,   // optional, for defaulted cases
        "notes": "..."           // optional
    }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key header."}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    app_id  = body.get("application_id", "").strip()
    outcome = body.get("outcome", "").lower().strip()
    valid_outcomes = {"repaid", "defaulted", "prepaid", "npa", "restructured", "written_off"}

    if not app_id:
        return JSONResponse({"error": "application_id is required."}, status_code=400)
    if outcome not in valid_outcomes:
        return JSONResponse({"error": f"outcome must be one of: {sorted(valid_outcomes)}"}, status_code=400)

    if not DATABASE_URL:
        return JSONResponse({"error": "No database configured."}, status_code=500)

    try:
        conn = get_db_conn()
        # Verify application exists and belongs to this bank
        rows = conn.run(
            "SELECT id, bank_name, decision FROM loan_applications WHERE application_id = :aid",
            aid=app_id
        )
        if not rows:
            conn.close()
            return JSONResponse({"error": "Application not found."}, status_code=404)

        app_bank = rows[0][1]
        if api_user.get("role") != "admin" and app_bank != api_user.get("bank_name"):
            conn.close()
            return JSONResponse({"error": "Access denied — application belongs to a different bank."}, status_code=403)

        conn.run(
            """INSERT INTO loan_outcomes (application_id, outcome, days_to_default, reported_by, notes)
               VALUES (:aid, :outcome, :dtd, :rby, :notes)
               ON CONFLICT (application_id) DO UPDATE
               SET outcome=EXCLUDED.outcome, days_to_default=EXCLUDED.days_to_default,
                   reported_by=EXCLUDED.reported_by, reported_at=NOW(), notes=EXCLUDED.notes""",
            aid=app_id, outcome=outcome,
            dtd=body.get("days_to_default"),
            rby=api_user["username"],
            notes=body.get("notes", "")[:500]
        )
        conn.close()

        write_audit_log("OUTCOME_FEEDBACK", api_user["username"], api_user.get("bank_name",""),
                        {"application_id": app_id, "outcome": outcome,
                         "days_to_default": body.get("days_to_default")})

        logger.info(f"Outcome feedback: {app_id} → {outcome} by {api_user['username']}")
        return JSONResponse({"ok": True, "application_id": app_id, "outcome": outcome})

    except Exception as e:
        logger.error(f"Outcome feedback error: {e}")
        return JSONResponse({"error": "Failed to record outcome."}, status_code=500)


# ── Application Retrieval API ──────────────────────────────────────────────────
@app.get("/api/v1/application/{application_id}")
@limiter.limit("60/minute")
async def get_application(
    request: Request,
    application_id: str,
    x_api_key: str = Header(default="")
):
    """
    Retrieve a stored loan decision by application ID.
    Useful for LMS / MuleSoft integration polling.
    Returns masked PAN/Aadhaar in applicant details.
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key header."}, status_code=401)

    if not DATABASE_URL:
        return JSONResponse({"error": "No database configured."}, status_code=500)

    try:
        conn = get_db_conn()
        rows = conn.run("""
            SELECT la.application_id, la.applicant_name, la.loan_type, la.loan_amount,
                   la.decision, la.risk_level, la.risk_score, la.confidence_score,
                   la.approved_amount, la.interest_rate, la.foir, la.cibil_score,
                   la.reason, la.recommendation, la.counter_offer, la.redecision_hints,
                   la.strengths, la.concerns, la.fraud_flags, la.documentation_required,
                   la.employment_source, la.income_source, la.bank_name, la.created_at,
                   la.cibil_pdf_parsed, la.bank_stmt_parsed, la.payslip_pdf_parsed,
                   lo.outcome, lo.days_to_default
            FROM loan_applications la
            LEFT JOIN loan_outcomes lo ON la.application_id = lo.application_id
            WHERE la.application_id = :aid
        """, aid=application_id)
        conn.close()

        if not rows:
            return JSONResponse({"error": "Application not found."}, status_code=404)

        r = rows[0]
        app_bank = r[22]

        if api_user.get("role") != "admin" and app_bank != api_user.get("bank_name"):
            return JSONResponse({"error": "Access denied."}, status_code=403)

        return JSONResponse({
            "application_id":      r[0],
            "applicant_name":      r[1],
            "loan_type":           r[2],
            "loan_amount":         float(r[3] or 0),
            "decision":            r[4],
            "risk_level":          r[5],
            "risk_score":          r[6],
            "confidence_score":    r[7],
            "approved_amount":     float(r[8] or 0),
            "interest_rate":       float(r[9] or 0),
            "foir":                float(r[10] or 0),
            "cibil_score":         r[11],
            "reason":              r[12],
            "recommendation":      r[13],
            "counter_offer":       r[14],
            "redecision_hints":    r[15],
            "strengths":           json.loads(r[16] or "[]"),
            "concerns":            json.loads(r[17] or "[]"),
            "fraud_flags":         json.loads(r[18] or "[]"),
            "documentation_required": json.loads(r[19] or "[]"),
            "employment_source":   r[20],
            "income_source":       r[21],
            "bank_name":           r[22],
            "created_at":          r[23].isoformat() if r[23] else None,
            "documents_used": {
                "cibil_pdf":    bool(r[24]),
                "bank_stmt":    bool(r[25]),
                "payslip":      bool(r[26]),
            },
            "outcome": {
                "status":          r[27],
                "days_to_default": r[28],
            } if r[27] else None,
        })
    except Exception as e:
        logger.error(f"get_application error: {e}")
        return JSONResponse({"error": "Failed to retrieve application."}, status_code=500)


# ── Audit Log API (admin only) ────────────────────────────────────────────────
@app.get("/api/v1/audit-logs")
@limiter.limit("30/minute")
async def get_audit_logs(
    request: Request,
    x_api_key: str = Header(default=""),
    limit: int = 50,
    event_type: str = None
):
    """Retrieve recent audit log entries. Admin only."""
    api_user = get_user_from_api_key(x_api_key)
    if not api_user or api_user.get("role") != "admin":
        return JSONResponse({"error": "Admin access required."}, status_code=403)

    if not DATABASE_URL:
        return JSONResponse({"error": "No database configured."}, status_code=500)

    try:
        conn = get_db_conn()
        limit = min(max(limit, 1), 200)
        if event_type:
            rows = conn.run(
                "SELECT event_type, application_id, username, bank_name, details, ip_address, created_at "
                "FROM audit_logs WHERE event_type = :et ORDER BY created_at DESC LIMIT :lim",
                et=event_type, lim=limit
            )
        else:
            rows = conn.run(
                "SELECT event_type, application_id, username, bank_name, details, ip_address, created_at "
                "FROM audit_logs ORDER BY created_at DESC LIMIT :lim",
                lim=limit
            )
        conn.close()
        return JSONResponse([{
            "event_type": r[0], "application_id": r[1], "username": r[2],
            "bank_name": r[3], "details": r[4], "ip": r[5],
            "created_at": r[6].isoformat() if r[6] else None
        } for r in rows])
    except Exception as e:
        logger.error(f"audit_logs error: {e}")
        return JSONResponse({"error": "Failed to retrieve audit logs."}, status_code=500)


# ══════════════════════════════════════════════════════════════════════════════
# ── v5.0 — 13 Advanced Banking Feature Endpoints ─────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. PAN / Aadhaar eKYC ─────────────────────────────────────────────────────
@app.post("/api/v1/kyc/pan")
@limiter.limit("20/minute")
async def kyc_pan(request: Request, x_api_key: str = Header(default="")):
    """
    PAN eKYC: Cross-check PAN + name + DOB against NSDL.
    Body: { application_id, pan, name, dob (YYYY-MM-DD) }
    Returns: { status, match_score, name_match, dob_match }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    pan   = (body.get("pan") or "").strip().upper()
    name  = (body.get("name") or "").strip()
    dob   = (body.get("dob") or "").strip()
    app_id = body.get("application_id", "")

    if not pan or len(pan) != 10:
        return JSONResponse({"error": "Valid 10-character PAN required."}, status_code=400)
    if not name:
        return JSONResponse({"error": "Applicant name required for KYC match."}, status_code=400)

    # Deterministic rule-based PAN validation
    pan_valid = (pan[0:5].isalpha() and pan[5:9].isdigit() and pan[9].isalpha())
    pan_type  = {"P": "Individual", "C": "Company", "H": "HUF", "F": "Firm",
                 "A": "AOP", "T": "Trust", "B": "BOI", "L": "Local Auth",
                 "J": "AJP", "G": "Govt"}.get(pan[3], "Other")

    # Simulate NSDL response (in production: call NSDL API / KYC aggregator)
    import re
    name_words   = set(re.sub(r'[^a-zA-Z ]', '', name).lower().split())
    match_score  = 85 if pan_valid else 40
    status       = "VERIFIED" if pan_valid and match_score >= 70 else "MISMATCH"

    pan_masked = mask_pan(pan)
    if DATABASE_URL:
        try:
            conn = get_db_conn()
            conn.run("""
                INSERT INTO kyc_records (application_id, kyc_type, identifier, name_on_kyc, dob_on_kyc,
                    status, match_score, verified_by)
                VALUES (:aid, 'PAN', :id, :name, :dob, :status, :score, :by)
            """, aid=app_id, id=pan_masked, name=name, dob=dob,
                status=status, score=match_score, by=api_user["username"])
            conn.close()
        except Exception as e:
            logger.warning(f"KYC PAN DB write error: {e}")

    write_audit_log("KYC_PAN", api_user["username"], api_user.get("bank_name", ""),
                    {"pan_masked": pan_masked, "status": status, "app_id": app_id})
    return JSONResponse({
        "ok": True, "kyc_type": "PAN",
        "pan_masked": pan_masked,
        "pan_type": pan_type,
        "pan_valid_format": pan_valid,
        "status": status,
        "match_score": match_score,
        "name_match": match_score >= 70,
        "note": "Simulated NSDL response — connect KYC aggregator (KARZA/IDfy/Signzy) for live verification."
    })


@app.post("/api/v1/kyc/aadhaar")
@limiter.limit("20/minute")
async def kyc_aadhaar(request: Request, x_api_key: str = Header(default="")):
    """
    Aadhaar OTP eKYC (offline XML / DigiLocker flow).
    Body: { application_id, aadhaar_last4, name, dob }
    Returns: { status, masked_uid, name_match, address_extracted }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    last4  = (body.get("aadhaar_last4") or "").strip()
    name   = (body.get("name") or "").strip()
    app_id = body.get("application_id", "")

    if not last4 or not last4.isdigit() or len(last4) != 4:
        return JSONResponse({"error": "Provide last 4 digits of Aadhaar."}, status_code=400)

    uid_masked = mask_aadhaar("XXXX" + last4)
    status     = "VERIFIED"  # Simulation; real flow uses UIDAI OTP API

    if DATABASE_URL:
        try:
            conn = get_db_conn()
            conn.run("""
                INSERT INTO kyc_records (application_id, kyc_type, identifier, name_on_kyc,
                    status, match_score, verified_by)
                VALUES (:aid, 'AADHAAR', :id, :name, :status, 80, :by)
            """, aid=app_id, id=uid_masked, name=name, status=status, by=api_user["username"])
            conn.close()
        except Exception as e:
            logger.warning(f"KYC Aadhaar DB write: {e}")

    write_audit_log("KYC_AADHAAR", api_user["username"], api_user.get("bank_name", ""),
                    {"uid_masked": uid_masked, "status": status, "app_id": app_id})
    return JSONResponse({
        "ok": True, "kyc_type": "AADHAAR",
        "uid_masked": uid_masked,
        "status": status,
        "name_match": True,
        "note": "Simulated UIDAI response — integrate UIDAI sandbox / DigiLocker for production."
    })


# ── 2. Document Tampering Detection ─────────────────────────────────────────
@app.post("/api/v1/tamper-detect")
@limiter.limit("10/minute")
async def tamper_detect(
    request:  Request,
    session:  str        = Cookie(default=None),
    file:     UploadFile = File(...),
):
    """
    AI-powered document tampering detection.
    Sends the document to Claude and asks for signs of digital alteration.
    Returns: { tampered: bool, confidence, flags, verdict }
    """
    user = verify_session(session)
    if not user:
        return JSONResponse({"error": "Session expired."}, status_code=401)

    fname = (file.filename or "").lower()
    if not fname.endswith(".pdf"):
        return JSONResponse({"error": "Only PDF files supported."}, status_code=400)

    content = await file.read()
    if len(content) > 15 * 1024 * 1024:
        return JSONResponse({"error": "File too large (max 15 MB)."}, status_code=400)

    def _pdf_text(pdf_bytes: bytes) -> str:
        if not PYPDF_AVAILABLE:
            return ""
        try:
            reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
            parts = []
            for i, page in enumerate(reader.pages[:5]):
                t = page.extract_text() or ""
                if t.strip():
                    parts.append(f"--- Page {i+1} ---\n{t}")
            return "\n".join(parts)[:40_000]
        except Exception:
            return ""

    doc_text = _pdf_text(content)
    if not doc_text:
        b64 = base64.standard_b64encode(content).decode()
        content_block = {
            "type": "document",
            "source": {"type": "base64", "media_type": "application/pdf", "data": b64}
        }
    else:
        content_block = {"type": "text", "text": f"=== DOCUMENT CONTENT ===\n{doc_text}"}

    tamper_prompt = """You are a forensic document analyst specialising in Indian financial document fraud.
Analyse the provided document for signs of tampering, forgery or digital manipulation.

Check for:
1. Font inconsistencies (different typefaces mid-line, pixel artefacts around digits)
2. Whitespace / alignment anomalies (common after copy-paste replacement of numbers)
3. Suspicious round numbers (salary exactly 100000 every month, CIBIL score exactly 750)
4. Date/sequence inconsistencies (statement months out of order, future dates)
5. Logo or letterhead anomalies
6. Watermark or security feature absence
7. Metadata mismatches (document claims 2024 but formatting suggests 2020)
8. Balance arithmetic errors (opening + credits - debits ≠ closing)

Return ONLY valid JSON:
{
  "tampered": true/false,
  "confidence": 0-100,
  "risk_level": "LOW" | "MEDIUM" | "HIGH",
  "flags": ["list of specific suspicious observations"],
  "verdict": "single sentence plain-English conclusion",
  "recommend_manual_review": true/false
}"""

    try:
        msg = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=800,
            messages=[{"role": "user", "content": [content_block, {"type": "text", "text": tamper_prompt}]}]
        )
        raw    = msg.content[0].text.strip().replace("```json", "").replace("```", "").strip()
        result = json.loads(raw)
    except json.JSONDecodeError:
        return JSONResponse({"error": "AI response parse error. Please retry."}, status_code=422)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)

    write_audit_log("TAMPER_DETECT", user["username"], user.get("bank_name", ""),
                    {"file": file.filename, "tampered": result.get("tampered"), "confidence": result.get("confidence")})
    return JSONResponse({"ok": True, "filename": file.filename, **result})


# ── 3. Scorecard Engine ─────────────────────────────────────────────────────
def _compute_scorecard(cibil: int, foir: float, dpd_30: int, dpd_90: int,
                        bounce: int, vintage: float, emp_type: str,
                        income: float, amb: float, enq: int, wo: bool) -> dict:
    """
    Deterministic 100-point scorecard (no AI).
    Based on Indian NBFC underwriting best practices.
    """
    score = 0
    breakdown = {}

    # CIBIL (max 30 pts)
    cibil_pts = 0
    if cibil >= 800:   cibil_pts = 30
    elif cibil >= 750: cibil_pts = 25
    elif cibil >= 700: cibil_pts = 18
    elif cibil >= 650: cibil_pts = 10
    elif cibil >= 600: cibil_pts = 5
    score += cibil_pts
    breakdown["CIBIL Score"] = {"points": cibil_pts, "max": 30}

    # FOIR (max 20 pts)
    foir_pts = 0
    if foir <= 30:   foir_pts = 20
    elif foir <= 40: foir_pts = 15
    elif foir <= 50: foir_pts = 10
    elif foir <= 55: foir_pts = 5
    score += foir_pts
    breakdown["FOIR"] = {"points": foir_pts, "max": 20}

    # DPD (max 15 pts)
    dpd_pts = 15 if dpd_30 == 0 else (8 if dpd_30 <= 1 else (2 if dpd_30 <= 3 else 0))
    if dpd_90 > 0: dpd_pts = 0
    score += dpd_pts
    breakdown["DPD History"] = {"points": dpd_pts, "max": 15}

    # Bounce (max 10 pts)
    bnc_pts = 10 if bounce == 0 else (7 if bounce <= 1 else (3 if bounce <= 3 else 0))
    score += bnc_pts
    breakdown["Cheque Bounces"] = {"points": bnc_pts, "max": 10}

    # Credit vintage (max 10 pts)
    vint_pts = 10 if vintage >= 7 else (7 if vintage >= 4 else (4 if vintage >= 2 else (1 if vintage > 0 else 0)))
    score += vint_pts
    breakdown["Credit Vintage"] = {"points": vint_pts, "max": 10}

    # Employment (max 8 pts)
    emp_pts = (8 if "Government" in emp_type or "PSU" in emp_type
               else 6 if "Salaried" in emp_type
               else 4 if "Professional" in emp_type
               else 3)
    score += emp_pts
    breakdown["Employment Stability"] = {"points": emp_pts, "max": 8}

    # AMB vs income (max 5 pts)
    amb_pts = 5 if (amb >= income and income > 0) else (3 if amb >= income * 0.5 else 1)
    score += amb_pts
    breakdown["Bank Balance Ratio"] = {"points": amb_pts, "max": 5}

    # Enquiries (max 2 pts)
    enq_pts = 2 if enq <= 2 else (1 if enq <= 4 else 0)
    score += enq_pts
    breakdown["Credit Enquiries"] = {"points": enq_pts, "max": 2}

    # Write-off penalty
    if wo: score = max(0, score - 20)

    grade = ("A+" if score >= 85 else "A" if score >= 75 else "B+" if score >= 65
             else "B" if score >= 55 else "C" if score >= 40 else "D")

    return {
        "total_score": min(score, 100),
        "max_score": 100,
        "grade": grade,
        "breakdown": breakdown,
        "verdict": (
            "Strong credit profile — recommend approval." if score >= 75 else
            "Moderate risk — conditional approval with monitoring." if score >= 55 else
            "High risk — require additional collateral or co-applicant." if score >= 40 else
            "Decline — credit profile does not meet minimum scorecard threshold."
        )
    }

@app.post("/api/v1/scorecard")
@limiter.limit("30/minute")
async def scorecard_api(request: Request, x_api_key: str = Header(default="")):
    """
    Run deterministic scorecard for any application data.
    No AI call — pure rule-based scoring.
    Body: { cibil_score, foir, dpd_30_count, dpd_90_count, bounce_count_6m,
            credit_vintage_yrs, employment_type, monthly_income,
            avg_monthly_balance, enquiries_6m, writeoff_settled }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        b = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    result = _compute_scorecard(
        cibil=int(b.get("cibil_score", 300)),
        foir=float(b.get("foir", 0)),
        dpd_30=int(b.get("dpd_30_count", 0)),
        dpd_90=int(b.get("dpd_90_count", 0)),
        bounce=int(b.get("bounce_count_6m", 0)),
        vintage=float(b.get("credit_vintage_yrs", 0)),
        emp_type=str(b.get("employment_type", "")),
        income=float(b.get("monthly_income", 0)),
        amb=float(b.get("avg_monthly_balance", 0)),
        enq=int(b.get("enquiries_6m", 0)),
        wo=str(b.get("writeoff_settled", "no")).lower() in ("yes", "true", "1"),
    )
    return JSONResponse({"ok": True, **result})


# ── 4. Account Aggregator (AA) Framework ────────────────────────────────────
@app.post("/api/v1/aa/consent")
@limiter.limit("20/minute")
async def aa_consent(request: Request, x_api_key: str = Header(default="")):
    """
    Initiate AA consent request (RBI Account Aggregator framework).
    Body: { application_id, customer_mobile, fip_ids, purpose, from_date, to_date }
    Returns: { consent_id, consent_handle, status, redirect_url }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    app_id   = body.get("application_id", generate_app_id())
    mobile   = (body.get("customer_mobile") or "").strip()
    fip_ids  = body.get("fip_ids", ["SBI-FIP", "HDFC-FIP", "ICICI-FIP"])
    purpose  = body.get("purpose", "Loan Underwriting")

    if not mobile or len(mobile) != 10:
        return JSONResponse({"error": "Valid 10-digit mobile number required."}, status_code=400)

    # Simulate Sahamati / AA aggregator response
    consent_id     = secrets.token_hex(16)
    consent_handle = f"AA-{consent_id[:8].upper()}"
    redirect_url   = f"https://aa-gateway.example.com/consent/{consent_handle}?mobile={mobile[-4:]}"

    write_audit_log("AA_CONSENT_INITIATE", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": app_id, "fip_count": len(fip_ids), "consent_id": consent_id})
    return JSONResponse({
        "ok": True,
        "application_id": app_id,
        "consent_id": consent_id,
        "consent_handle": consent_handle,
        "status": "PENDING",
        "redirect_url": redirect_url,
        "fip_ids": fip_ids,
        "purpose": purpose,
        "note": "Simulated Sahamati AA response — integrate live AA gateway (Perfios/Finvu/OneMoney) for production.",
        "expires_in_hours": 24
    })


@app.get("/api/v1/aa/data/{consent_id}")
@limiter.limit("30/minute")
async def aa_fetch_data(request: Request, consent_id: str,
                        x_api_key: str = Header(default="")):
    """
    Fetch AA financial data after consent approval.
    Returns: { status, accounts, months_available, summary }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)

    # Simulate AA data fetch
    return JSONResponse({
        "ok": True,
        "consent_id": consent_id,
        "status": "APPROVED",
        "accounts": [
            {"fip": "SBI-FIP", "account_type": "SAVINGS", "masked_id": "XXXX6789",
             "months_available": 12, "avg_balance": 45000, "salary_credited": True},
            {"fip": "HDFC-FIP", "account_type": "SAVINGS", "masked_id": "XXXX3421",
             "months_available": 6, "avg_balance": 12000, "salary_credited": False},
        ],
        "note": "Simulated AA data — integrate Sahamati / FIP APIs for live data."
    })


# ── 5. Multi-Bureau Credit Check ────────────────────────────────────────────
@app.post("/api/v1/multi-bureau")
@limiter.limit("15/minute")
async def multi_bureau(request: Request, x_api_key: str = Header(default="")):
    """
    Trigger credit pull from multiple bureaus (CIBIL + Experian + CRIF + Equifax).
    Body: { application_id, pan, name, dob, mobile }
    Returns: { scores_by_bureau, best_score, worst_score, recommendation }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    pan    = (body.get("pan") or "").strip().upper()
    name   = (body.get("name") or "").strip()
    app_id = body.get("application_id", "")

    if not pan or not name:
        return JSONResponse({"error": "PAN and name required for bureau pull."}, status_code=400)

    pan_masked = mask_pan(pan)

    # Simulate multi-bureau scores (deterministic based on PAN hash)
    seed = int(hashlib.md5(pan.encode()).hexdigest()[:6], 16)
    base = 600 + (seed % 250)
    scores = {
        "CIBIL":    min(900, base + random.randint(-10, 20)),
        "Experian": min(900, base + random.randint(-15, 15)),
        "CRIF":     min(900, base + random.randint(-20, 10)),
        "Equifax":  min(900, base + random.randint(-5, 25)),
    }
    best  = max(scores.values())
    worst = min(scores.values())
    spread = best - worst

    recommendation = (
        "Consistent scores across bureaus — use CIBIL as primary." if spread <= 30 else
        "Moderate bureau divergence — investigate discrepant bureau report." if spread <= 60 else
        "High divergence — manual review required before underwriting."
    )

    write_audit_log("MULTI_BUREAU", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": app_id, "pan_masked": pan_masked, "best": best, "spread": spread})
    return JSONResponse({
        "ok": True, "application_id": app_id,
        "pan_masked": pan_masked,
        "scores_by_bureau": scores,
        "best_score": best, "worst_score": worst,
        "spread": spread,
        "recommendation": recommendation,
        "primary_bureau": "CIBIL",
        "note": "Simulated scores — integrate TransUnion CIBIL, Experian India, CRIF High Mark, Equifax India APIs."
    })


# ── 6. GST Underwriting ─────────────────────────────────────────────────────
@app.post("/api/v1/gst-analysis")
@limiter.limit("20/minute")
async def gst_analysis(request: Request, x_api_key: str = Header(default="")):
    """
    AI-powered GST return analysis for business loan underwriting.
    Body: { application_id, gstin, monthly_gst_data: [...], loan_amount }
    Returns: { turnover_trend, tax_compliance, eligible_income, flags }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    gstin       = (body.get("gstin") or "").strip().upper()
    monthly_data = body.get("monthly_gst_data", [])
    loan_amount  = float(body.get("loan_amount", 0))
    app_id       = body.get("application_id", "")

    if not gstin or len(gstin) != 15:
        return JSONResponse({"error": "Valid 15-character GSTIN required."}, status_code=400)

    # Deterministic GST analytics (no AI call needed for numbers)
    turnovers = [float(m.get("turnover", 0)) for m in monthly_data if m.get("turnover")]
    taxes     = [float(m.get("tax_paid", 0)) for m in monthly_data if m.get("tax_paid")]

    avg_turnover   = round(sum(turnovers) / len(turnovers), 0) if turnovers else 0
    annual_turnover = avg_turnover * 12
    effective_rate  = round(sum(taxes) / sum(turnovers) * 100, 2) if turnovers and taxes else 0
    trend = "GROWING" if (len(turnovers) >= 3 and turnovers[-1] > turnovers[0] * 1.1) else             "DECLINING" if (len(turnovers) >= 3 and turnovers[-1] < turnovers[0] * 0.9) else "STABLE"

    # Banking income = 15-25% of turnover for business loans
    eligible_income = round(avg_turnover * 0.20, 0)
    flags = []
    if effective_rate < 2: flags.append("Very low GST effective rate — verify return authenticity")
    if trend == "DECLINING": flags.append("Turnover declining — business stress signal")
    if loan_amount > annual_turnover * 0.5: flags.append("Loan amount >50% of annual turnover — high leverage")
    if not turnovers: flags.append("No GST data provided — manual GSTIN verification needed")

    gstin_state = {"07": "Delhi", "27": "Maharashtra", "33": "Tamil Nadu",
                   "29": "Karnataka", "09": "Uttar Pradesh"}.get(gstin[:2], "State " + gstin[:2])

    write_audit_log("GST_ANALYSIS", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": app_id, "gstin": gstin[:5] + "****", "trend": trend, "avg_turnover": avg_turnover})
    return JSONResponse({
        "ok": True, "application_id": app_id,
        "gstin": gstin[:5] + "****" + gstin[-3:],
        "gstin_state": gstin_state,
        "avg_monthly_turnover": avg_turnover,
        "annual_turnover": annual_turnover,
        "effective_tax_rate_pct": effective_rate,
        "turnover_trend": trend,
        "eligible_monthly_income": eligible_income,
        "months_analyzed": len(turnovers),
        "flags": flags,
        "note": "Integrate GSP/GSTN sandbox API for live GSTR-3B / GSTR-1 pull."
    })


# ── 7. Video KYC (V-KYC) ────────────────────────────────────────────────────
@app.post("/api/v1/vkyc/schedule")
@limiter.limit("15/minute")
async def vkyc_schedule(request: Request, x_api_key: str = Header(default="")):
    """
    Schedule a V-KYC session (RBI mandated for digital lending).
    Body: { application_id, applicant_name, mobile, preferred_slot }
    Returns: { session_id, scheduled_at, agent_link, customer_link }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    app_id = body.get("application_id", generate_app_id())
    name   = body.get("applicant_name", "")
    mobile = body.get("mobile", "")
    slot   = body.get("preferred_slot", "")

    session_id  = secrets.token_hex(12)
    agent_token = secrets.token_hex(8)
    cust_token  = secrets.token_hex(8)

    write_audit_log("VKYC_SCHEDULE", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": app_id, "session_id": session_id, "mobile_last4": mobile[-4:] if len(mobile) >= 4 else ""})
    return JSONResponse({
        "ok": True, "application_id": app_id,
        "session_id": session_id,
        "status": "SCHEDULED",
        "preferred_slot": slot or "Next available",
        "agent_link": f"https://vkyc.example.com/agent/{session_id}?t={agent_token}",
        "customer_link": f"https://vkyc.example.com/c/{session_id}?t={cust_token}",
        "sms_sent": bool(mobile),
        "note": "Simulated V-KYC session — integrate Aadhaar Paperless KYC or IDfy / HyperVerge V-KYC SDK."
    })


@app.get("/api/v1/vkyc/status/{session_id}")
@limiter.limit("30/minute")
async def vkyc_status(request: Request, session_id: str,
                       x_api_key: str = Header(default="")):
    """Check V-KYC session status."""
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    return JSONResponse({
        "ok": True, "session_id": session_id,
        "status": "COMPLETED",
        "liveness_check": "PASSED",
        "face_match_score": 94,
        "id_verified": True,
        "note": "Simulated status — real status requires live V-KYC SDK webhook."
    })


# ── 8. e-Sign ────────────────────────────────────────────────────────────────
@app.post("/api/v1/esign")
@limiter.limit("15/minute")
async def esign(request: Request, x_api_key: str = Header(default="")):
    """
    Initiate Aadhaar-based e-Sign for loan agreement.
    Body: { application_id, applicant_name, mobile, email, document_type }
    Returns: { esign_id, redirect_url, expires_at }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    app_id   = body.get("application_id", "")
    doc_type = body.get("document_type", "Loan Agreement")
    esign_id = secrets.token_hex(16)

    write_audit_log("ESIGN_INITIATE", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": app_id, "doc_type": doc_type, "esign_id": esign_id})
    return JSONResponse({
        "ok": True, "application_id": app_id,
        "esign_id": esign_id,
        "document_type": doc_type,
        "status": "PENDING",
        "redirect_url": f"https://esign.example.com/sign/{esign_id}",
        "expires_in_minutes": 30,
        "note": "Simulated e-Sign — integrate NSDL e-Gov / Leegality / SignDesk for Aadhaar eSign."
    })


# ── 9. e-NACH Mandate ───────────────────────────────────────────────────────
@app.post("/api/v1/nach/mandate")
@limiter.limit("15/minute")
async def nach_mandate(request: Request, x_api_key: str = Header(default="")):
    """
    Create NACH mandate for auto-debit of EMIs.
    Body: { application_id, bank_account, ifsc, emi_amount, start_date, tenure_months }
    Returns: { mandate_id, umrn, status, presentation_date }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    app_id     = body.get("application_id", "")
    emi_amount = float(body.get("emi_amount", 0))
    ifsc       = (body.get("ifsc") or "").strip().upper()
    start_date = body.get("start_date", "")

    if emi_amount <= 0:
        return JSONResponse({"error": "EMI amount must be greater than 0."}, status_code=400)
    if not ifsc:
        return JSONResponse({"error": "IFSC code is required."}, status_code=400)

    mandate_id = "NACH" + secrets.token_hex(8).upper()
    umrn       = "UMRN" + secrets.token_hex(6).upper()

    write_audit_log("NACH_MANDATE", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": app_id, "emi": emi_amount, "ifsc": ifsc, "mandate_id": mandate_id})
    return JSONResponse({
        "ok": True, "application_id": app_id,
        "mandate_id": mandate_id,
        "umrn": umrn,
        "status": "PENDING_REGISTRATION",
        "emi_amount": emi_amount,
        "ifsc": ifsc,
        "start_date": start_date,
        "frequency": "MONTHLY",
        "note": "Simulated NACH mandate — integrate NPCI / Razorpay / Cashfree NACH API for production."
    })


# ── 10. WhatsApp Bot Webhook ─────────────────────────────────────────────────
@app.post("/api/v1/whatsapp/webhook")
async def whatsapp_webhook(request: Request):
    """
    WhatsApp Business API webhook for loan status notifications.
    Accepts Meta/WABA webhook events and sends automated status updates.
    Body: (Meta webhook JSON structure)
    Returns: 200 OK always (Meta requires this)
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"status": "ok"})

    entry = (body.get("entry") or [{}])[0]
    changes = (entry.get("changes") or [{}])[0]
    value = changes.get("value", {})
    messages = value.get("messages", [])

    for msg in messages:
        phone  = msg.get("from", "")
        text   = (msg.get("text") or {}).get("body", "").strip().lower()
        msg_id = msg.get("id", "")

        # Parse loan status query
        if text.startswith("status") or text.startswith("loan"):
            parts  = text.split()
            app_id = next((p.upper() for p in parts if p.upper().startswith("LN-")), None)
            logger.info(f"WhatsApp loan status query: phone={phone[-4:]} app_id={app_id}")
            # In production: look up app_id from DB and send reply via Meta WABA API

    return JSONResponse({"status": "ok"})


@app.get("/api/v1/whatsapp/send")
@limiter.limit("10/minute")
async def whatsapp_send(request: Request, x_api_key: str = Header(default=""),
                        application_id: str = "", mobile: str = "", template: str = "loan_status"):
    """Send WhatsApp notification for a loan application."""
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    if not mobile or not application_id:
        return JSONResponse({"error": "mobile and application_id required."}, status_code=400)

    templates = {
        "loan_status": f"Your loan application {application_id} has been processed. Login to check your decision.",
        "doc_reminder": f"Documents pending for {application_id}. Please upload to proceed.",
        "emi_reminder": f"Your EMI for loan {application_id} is due in 3 days. Auto-debit via NACH is set up.",
        "approval":     f"Congratulations! Your loan {application_id} is APPROVED. Disbursement in 2–3 working days.",
    }
    message = templates.get(template, templates["loan_status"])
    write_audit_log("WHATSAPP_SEND", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": application_id, "mobile_last4": mobile[-4:], "template": template})
    return JSONResponse({
        "ok": True, "application_id": application_id,
        "mobile_last4": mobile[-4:], "template": template,
        "message_preview": message,
        "status": "QUEUED",
        "note": "Simulated send — integrate Meta WhatsApp Business API / Gupshup / Kaleyra for production."
    })


# ── 11. Collections Module ──────────────────────────────────────────────────
@app.get("/api/v1/collections/{application_id}")
@limiter.limit("30/minute")
async def get_collection(request: Request, application_id: str,
                          x_api_key: str = Header(default="")):
    """Retrieve collections record for a loan application."""
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    if not DATABASE_URL:
        return JSONResponse({"error": "No database configured."}, status_code=500)
    try:
        conn = get_db_conn()
        rows = conn.run(
            """SELECT dpd_bucket, outstanding, last_payment, last_payment_dt,
                      next_action, agent_assigned, status, updated_at
               FROM collections WHERE application_id = :aid
               ORDER BY updated_at DESC LIMIT 1""",
            aid=application_id
        )
        conn.close()
        if not rows:
            return JSONResponse({"error": "No collections record found."}, status_code=404)
        r = rows[0]
        return JSONResponse({
            "application_id": application_id,
            "dpd_bucket": r[0], "outstanding": float(r[1] or 0),
            "last_payment": float(r[2] or 0),
            "last_payment_date": r[3].isoformat() if r[3] else None,
            "next_action": r[4], "agent_assigned": r[5],
            "status": r[6],
            "updated_at": r[7].isoformat() if r[7] else None,
        })
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/api/v1/collections/{application_id}/update")
@limiter.limit("20/minute")
async def update_collection(request: Request, application_id: str,
                             x_api_key: str = Header(default="")):
    """
    Update collections record (payment received, DPD update, next action).
    Body: { dpd_bucket, outstanding, last_payment, next_action, agent_assigned, status }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    if not DATABASE_URL:
        return JSONResponse({"error": "No database configured."}, status_code=500)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    valid_statuses = {"REGULAR", "DELINQUENT", "NPA", "RESTRUCTURED", "WRITTEN_OFF", "CLOSED"}
    status = body.get("status", "REGULAR").upper()
    if status not in valid_statuses:
        return JSONResponse({"error": f"status must be one of: {sorted(valid_statuses)}"}, status_code=400)

    try:
        conn = get_db_conn()
        conn.run("""
            INSERT INTO collections (application_id, dpd_bucket, outstanding, last_payment,
                next_action, agent_assigned, status, updated_by)
            VALUES (:aid, :dpd, :ost, :lp, :na, :ag, :st, :by)
        """, aid=application_id,
            dpd=body.get("dpd_bucket", "0"),
            ost=float(body.get("outstanding", 0)),
            lp=float(body.get("last_payment", 0)),
            na=str(body.get("next_action", ""))[:100],
            ag=str(body.get("agent_assigned", ""))[:50],
            st=status, by=api_user["username"]
        )
        conn.close()
        write_audit_log("COLLECTION_UPDATE", api_user["username"], api_user.get("bank_name", ""),
                        {"app_id": application_id, "status": status, "dpd": body.get("dpd_bucket")})
        return JSONResponse({"ok": True, "application_id": application_id, "status": status})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── 12. Co-Lending Module ────────────────────────────────────────────────────
CO_LENDING_PARTNERS = {
    "SBI":        {"min_ticket": 500000,  "max_ticket": 10000000, "bank_share_pct": 80, "rate_spread": -1.5},
    "Bank of Baroda": {"min_ticket": 300000, "max_ticket": 5000000, "bank_share_pct": 75, "rate_spread": -1.0},
    "IDFC First": {"min_ticket": 100000,  "max_ticket": 2000000,  "bank_share_pct": 70, "rate_spread": -0.5},
    "Piramal":    {"min_ticket": 500000,  "max_ticket": 5000000,  "bank_share_pct": 80, "rate_spread": -0.8},
}

@app.get("/api/v1/colending/partners")
@limiter.limit("30/minute")
async def colending_partners(request: Request, x_api_key: str = Header(default="")):
    """List available co-lending partners and their terms."""
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    return JSONResponse({"ok": True, "partners": CO_LENDING_PARTNERS,
                          "note": "NBFC retains 20-30% of loan; partner bank funds balance under RBI Co-Lending Guidelines."})


@app.post("/api/v1/colending/propose")
@limiter.limit("15/minute")
async def colending_propose(request: Request, x_api_key: str = Header(default="")):
    """
    Propose a co-lending arrangement for an application.
    Body: { application_id, loan_amount, interest_rate, partner_bank }
    Returns: { blended_rate, nbfc_share, bank_share, emi_estimate }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    app_id       = body.get("application_id", "")
    loan_amount  = float(body.get("loan_amount", 0))
    nbfc_rate    = float(body.get("interest_rate", 14))
    partner_name = body.get("partner_bank", "SBI")
    partner      = CO_LENDING_PARTNERS.get(partner_name, CO_LENDING_PARTNERS["SBI"])

    bank_share_pct = partner["bank_share_pct"]
    nbfc_share_pct = 100 - bank_share_pct
    partner_rate   = max(nbfc_rate + partner["rate_spread"], 7.5)
    blended_rate   = round((nbfc_rate * nbfc_share_pct + partner_rate * bank_share_pct) / 100, 2)

    if DATABASE_URL:
        try:
            conn = get_db_conn()
            conn.run("""
                INSERT INTO colending_records (application_id, partner_bank, nbfc_share_pct,
                    bank_share_pct, partner_rate, blended_rate, created_by)
                VALUES (:aid, :pb, :ns, :bs, :pr, :br, :by)
                ON CONFLICT (application_id) DO UPDATE
                SET partner_bank=EXCLUDED.partner_bank, blended_rate=EXCLUDED.blended_rate,
                    updated_at=NOW()
            """, aid=app_id, pb=partner_name, ns=nbfc_share_pct,
                bs=bank_share_pct, pr=partner_rate, br=blended_rate, by=api_user["username"])
            conn.close()
        except Exception as e:
            logger.warning(f"Co-lending DB write: {e}")

    write_audit_log("COLENDING_PROPOSE", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": app_id, "partner": partner_name, "blended_rate": blended_rate})
    return JSONResponse({
        "ok": True, "application_id": app_id,
        "partner_bank": partner_name,
        "loan_amount": loan_amount,
        "nbfc_share_pct": nbfc_share_pct,
        "nbfc_share_amount": round(loan_amount * nbfc_share_pct / 100, 0),
        "bank_share_pct": bank_share_pct,
        "bank_share_amount": round(loan_amount * bank_share_pct / 100, 0),
        "nbfc_rate": nbfc_rate,
        "partner_rate": partner_rate,
        "blended_rate": blended_rate,
        "rate_benefit_to_borrower": round(nbfc_rate - blended_rate, 2),
        "note": "RBI Co-Lending Model (CLM) per circular RBI/2020-21/63."
    })


# ── 13. AML Screening ────────────────────────────────────────────────────────
AML_WATCHLISTS = [
    "FATF High-Risk Jurisdictions", "RBI Caution List",
    "UN Security Council Sanctions", "OFAC SDN List",
    "ED/CBI Look-Out Circular", "SEBI Debarred Entities"
]

@app.post("/api/v1/aml/screen")
@limiter.limit("20/minute")
async def aml_screen(request: Request, x_api_key: str = Header(default="")):
    """
    AML/KYC screening against sanction lists and watchlists.
    Body: { application_id, name, pan, dob, employer_name, loan_amount }
    Returns: { risk_level, match_found, lists_checked, flags }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    name        = (body.get("name") or "").strip()
    pan         = (body.get("pan") or "").strip().upper()
    app_id      = body.get("application_id", "")
    loan_amount = float(body.get("loan_amount", 0))

    if not name:
        return JSONResponse({"error": "Applicant name required for AML screening."}, status_code=400)

    pan_masked = mask_pan(pan) if pan else ""

    # Deterministic rule-based AML risk assessment (no false positives in simulation)
    risk_flags = []
    if loan_amount > 5_000_000:
        risk_flags.append("Large transaction (>Rs 50L) — enhanced due diligence required per PMLA")
    if "cash" in name.lower() or "bullion" in name.lower():
        risk_flags.append("Name contains high-risk keywords — manual review required")

    # Simulate watchlist check (no real names matched in simulation)
    match_found = False
    risk_level  = "HIGH" if match_found else ("MEDIUM" if risk_flags else "LOW")

    if DATABASE_URL:
        try:
            conn = get_db_conn()
            conn.run("""
                INSERT INTO aml_screenings (application_id, applicant_name, pan_masked,
                    risk_level, match_found, match_details, screened_by, lists_checked)
                VALUES (:aid, :name, :pan, :rl, :mf, :md, :by, :lists)
            """, aid=app_id, name=name, pan=pan_masked,
                rl=risk_level, mf=match_found,
                md="; ".join(risk_flags) if risk_flags else None,
                by=api_user["username"],
                lists=json.dumps(AML_WATCHLISTS)
            )
            conn.close()
        except Exception as e:
            logger.warning(f"AML DB write: {e}")

    write_audit_log("AML_SCREEN", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": app_id, "risk_level": risk_level, "match": match_found, "pan_masked": pan_masked})
    return JSONResponse({
        "ok": True, "application_id": app_id,
        "name_screened": name,
        "pan_masked": pan_masked,
        "risk_level": risk_level,
        "match_found": match_found,
        "lists_checked": AML_WATCHLISTS,
        "flags": risk_flags,
        "recommendation": (
            "CLEAR — no adverse findings. Proceed with standard KYC." if risk_level == "LOW" else
            "ENHANCED DUE DILIGENCE required before disbursement." if risk_level == "MEDIUM" else
            "ESCALATE to Compliance / MLRO immediately."
        ),
        "note": "Simulated AML check — integrate World-Check / Refinitiv / Dow Jones Risk for production."
    })


# ── 14. Alternate Credit Scoring (Thin File / NTC borrowers) ─────────────────
@app.post("/api/v1/alternate-score")
@limiter.limit("15/minute")
async def alternate_score(request: Request, x_api_key: str = Header(default="")):
    """
    Alternate credit score for New-to-Credit (NTC) / thin-file borrowers.
    Uses utility payments, mobile usage, UPI behaviour instead of bureau score.
    Body: { application_id, mobile_tenure_months, upi_txn_monthly_avg,
            utility_payments_on_time, avg_mobile_recharge, rental_payment_history,
            monthly_income, employment_type }
    Returns: { alternate_score, grade, eligibility, recommended_max_loan }
    """
    api_user = get_user_from_api_key(x_api_key)
    if not api_user:
        return JSONResponse({"error": "Invalid or missing X-API-Key."}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    mobile_tenure   = int(body.get("mobile_tenure_months", 0))
    upi_avg         = float(body.get("upi_txn_monthly_avg", 0))
    utility_ontime  = bool(body.get("utility_payments_on_time", True))
    mobile_recharge = float(body.get("avg_mobile_recharge", 0))
    rental_history  = bool(body.get("rental_payment_history", False))
    income          = float(body.get("monthly_income", 0))
    emp_type        = str(body.get("employment_type", ""))
    app_id          = body.get("application_id", "")

    # Alternate scoring logic (industry-standard NTC model)
    score = 0
    breakdown = {}

    # Mobile tenure (max 20)
    m_pts = min(20, mobile_tenure // 6 * 4)
    score += m_pts; breakdown["Mobile Tenure"] = {"points": m_pts, "max": 20}

    # UPI behaviour (max 25)
    u_pts = 25 if upi_avg > 30 else 18 if upi_avg > 15 else 10 if upi_avg > 5 else 3
    score += u_pts; breakdown["UPI Activity"] = {"points": u_pts, "max": 25}

    # Utility payments (max 20)
    ut_pts = 20 if utility_ontime else 5
    score += ut_pts; breakdown["Utility Payments"] = {"points": ut_pts, "max": 20}

    # Mobile recharge regularity (max 10)
    r_pts = 10 if mobile_recharge >= 300 else 6 if mobile_recharge >= 150 else 2
    score += r_pts; breakdown["Mobile Recharge"] = {"points": r_pts, "max": 10}

    # Rental history (max 15)
    rh_pts = 15 if rental_history else 0
    score += rh_pts; breakdown["Rental History"] = {"points": rh_pts, "max": 15}

    # Employment (max 10)
    e_pts = 10 if "Salaried" in emp_type else 7 if emp_type else 4
    score += e_pts; breakdown["Employment"] = {"points": e_pts, "max": 10}

    score = min(score, 100)
    grade = "A" if score >= 75 else "B" if score >= 55 else "C" if score >= 40 else "D"
    eligible = score >= 40
    max_loan = round(income * (20 if score >= 75 else 12 if score >= 55 else 6), -3) if income > 0 else 0

    write_audit_log("ALTERNATE_SCORE", api_user["username"], api_user.get("bank_name", ""),
                    {"app_id": app_id, "score": score, "grade": grade, "eligible": eligible})
    return JSONResponse({
        "ok": True, "application_id": app_id,
        "alternate_score": score,
        "max_possible": 100,
        "grade": grade,
        "eligible_for_ntc_loan": eligible,
        "recommended_max_loan": max_loan,
        "breakdown": breakdown,
        "recommendation": (
            f"NTC borrower eligible — max loan Rs {max_loan:,.0f} at MFI/micro-loan rates." if eligible else
            "Score too low — recommend 6-month UPI/utility track record before re-application."
        ),
        "note": "Integrate Bureau's NTC score (CIBIL NTC, Experian Thin File) or alt-data APIs for production."
    })

@app.get("/health")
def health():
    db_ok = False
    if DATABASE_URL:
        try:
            conn = get_db_conn(); conn.run("SELECT 1"); conn.close(); db_ok = True
        except Exception: pass
    return {
        "status": "ok",
        "service": "NBFC AI Platform v5.0",
        "loan_types": len(LOAN_RULES),
        "database": "connected" if db_ok else "not connected",
        "v4_features": [
            "Payslip + CIBIL + Bank Statement PDF parsing", "Document priority engine",
            "Multi-user / multi-bank", "Risk-based pricing", "Fraud detection engine",
            "Confidence scoring", "Re-decision hints", "Audit logs (PII-masked)",
            "Outcome feedback loop", "Application retrieval API"
        ],
        "v5_features": [
            "PAN eKYC (/api/v1/kyc/pan)",
            "Aadhaar eKYC (/api/v1/kyc/aadhaar)",
            "Document Tampering Detection (/api/v1/tamper-detect)",
            "Deterministic Scorecard Engine (/api/v1/scorecard)",
            "Account Aggregator Framework (/api/v1/aa/consent + /aa/data)",
            "Multi-Bureau Credit Check (/api/v1/multi-bureau)",
            "GST Underwriting Analytics (/api/v1/gst-analysis)",
            "Video KYC Scheduling (/api/v1/vkyc/schedule + /status)",
            "e-Sign Aadhaar (/api/v1/esign)",
            "e-NACH Mandate (/api/v1/nach/mandate)",
            "WhatsApp Bot Webhook (/api/v1/whatsapp/webhook + /send)",
            "Collections Module (/api/v1/collections)",
            "Co-Lending Module (/api/v1/colending)",
            "AML / Sanctions Screening (/api/v1/aml/screen)",
            "Alternate Credit Scoring NTC (/api/v1/alternate-score)",
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
