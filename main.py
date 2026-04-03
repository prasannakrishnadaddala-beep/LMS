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

# ── Startup validation ─────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
if not ANTHROPIC_API_KEY:
    raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set")

DATABASE_URL   = os.environ.get("DATABASE_URL", "")
SECRET_KEY     = os.environ.get("SECRET_KEY", secrets.token_hex(32))
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme123")

# ── App setup ──────────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="NBFC AI Platform v3.0")
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

def init_db():
    try:
        conn = get_db_conn()
        conn.run("""
            CREATE TABLE IF NOT EXISTS loan_applications (
                id                    SERIAL PRIMARY KEY,
                application_id        VARCHAR(30)   UNIQUE NOT NULL,
                applicant_name        VARCHAR(100),
                age                   INTEGER,
                employment_type       VARCHAR(60),
                employer_name         VARCHAR(100),
                loan_type             VARCHAR(60),
                loan_amount           NUMERIC(15,2),
                loan_tenure           INTEGER,
                cibil_score           INTEGER,
                dpd_30_count          INTEGER       DEFAULT 0,
                dpd_60_count          INTEGER       DEFAULT 0,
                dpd_90_count          INTEGER       DEFAULT 0,
                enquiries_6m          INTEGER       DEFAULT 0,
                credit_vintage_yrs    NUMERIC(4,1)  DEFAULT 0,
                avg_monthly_balance   NUMERIC(15,2) DEFAULT 0,
                bounce_count_6m       INTEGER       DEFAULT 0,
                monthly_income        NUMERIC(15,2),
                itr_income            NUMERIC(15,2) DEFAULT 0,
                gst_turnover          NUMERIC(15,2) DEFAULT 0,
                decision              VARCHAR(20),
                policy_violations     TEXT          DEFAULT '[]',
                risk_level            VARCHAR(10),
                risk_score            INTEGER,
                approved_amount       NUMERIC(15,2),
                interest_rate         NUMERIC(5,2),
                foir                  NUMERIC(5,1),
                ltv                   NUMERIC(5,1),
                emi_estimate          NUMERIC(15,2),
                fraud_flags           TEXT          DEFAULT '[]',
                regulatory_flags      TEXT          DEFAULT '[]',
                strengths             TEXT          DEFAULT '[]',
                concerns              TEXT          DEFAULT '[]',
                documentation_required TEXT         DEFAULT '[]',
                reason                TEXT,
                recommendation        TEXT,
                counter_offer         TEXT,
                bureau_assessment     TEXT,
                cashflow_assessment   TEXT,
                created_at            TIMESTAMPTZ   DEFAULT NOW()
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


# ── Utilities ──────────────────────────────────────────────────────────────────
def generate_app_id() -> str:
    today  = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))
    return f"LN-{today}-{suffix}"

def verify_session(session) -> str | None:
    if not session:
        return None
    try:
        data = serializer.loads(session, max_age=86400)
        return data.get("username")
    except (BadSignature, SignatureExpired):
        return None


# ── Auth ───────────────────────────────────────────────────────────────────────
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    if username.strip() == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        token = serializer.dumps({"username": username.strip()})
        resp  = RedirectResponse(url="/", status_code=303)
        resp.set_cookie("session", token, httponly=True, max_age=86400, samesite="lax")
        return resp
    return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials."})

@app.post("/logout")
def logout():
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("session")
    return resp


# ── Main pages ─────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home(request: Request, session: str = Cookie(default=None)):
    username = verify_session(session)
    if not username:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse("index.html", {
        "request": request, "loan_types": list(LOAN_RULES.keys()), "username": username
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
                       interest_rate, foir, cibil_score, employment_type, created_at,
                       dpd_30_count, dpd_90_count, enquiries_6m, bounce_count_6m
                FROM loan_applications ORDER BY created_at DESC LIMIT 100
            """)
            for r in rows:
                applications.append({
                    "application_id":  r[0], "applicant_name": r[1],
                    "loan_type":       r[2], "loan_amount":    float(r[3] or 0),
                    "decision":        r[4], "risk_level":     r[5],
                    "risk_score":      r[6], "approved_amount":float(r[7] or 0),
                    "interest_rate":   float(r[8] or 0), "foir": float(r[9] or 0),
                    "cibil_score":     r[10], "employment_type": r[11],
                    "created_at":      r[12].strftime("%d %b %Y, %I:%M %p") if r[12] else "",
                    "dpd_30_count":    r[13], "dpd_90_count": r[14],
                    "enquiries_6m":    r[15], "bounce_count_6m": r[16],
                })
            counts = conn.run("""
                SELECT COUNT(*),
                    COUNT(*) FILTER (WHERE decision='APPROVED'),
                    COUNT(*) FILTER (WHERE decision='REJECTED'),
                    COUNT(*) FILTER (WHERE decision='CONDITIONAL')
                FROM loan_applications
            """)
            if counts:
                t, a, r_, c = counts[0]
                t = int(t or 0); a = int(a or 0)
                stats = {"total": t, "approved": a, "rejected": int(r_ or 0),
                         "conditional": int(c or 0),
                         "approval_rate": round((a/t*100) if t > 0 else 0, 1)}
            conn.close()
        except Exception as e:
            logger.error(f"Dashboard error: {e}")

    return templates.TemplateResponse("dashboard.html", {
        "request": request, "username": username,
        "stats": stats, "applications": applications
    })


# ── Loan analysis ──────────────────────────────────────────────────────────────
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
    secured_unsecured_ratio: str = Form(""),
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
):
    if not verify_session(session):
        return JSONResponse({"error": "Session expired. Please log in again."}, status_code=401)

    full_name     = full_name.strip()[:100]
    loan_purpose  = loan_purpose.strip()[:300]
    employer_name = employer_name.strip()[:100]
    wo_bool       = writeoff_settled.lower() in ("yes", "true", "1", "on")
    sal_reg_bool  = salary_credits_regular.lower() in ("yes", "true", "1", "on")

    if loan_type not in LOAN_RULES:
        return JSONResponse({"error": "Invalid loan type."}, status_code=400)

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

    if policy_violations:
        app_id = generate_app_id()
        result = {
            "application_id": app_id, "decision": "REJECTED",
            "risk_level": "HIGH", "risk_score": 95,
            "approved_amount": 0, "recommended_interest_rate": 0,
            "processing_fee": 0, "max_eligible_tenure": 0,
            "fraud_flags": [], "regulatory_flags": [],
            "bureau_assessment": f"CIBIL {cibil_score}. DPD 90+: {dpd_90_count}. Enquiries 6m: {enquiries_6m}.",
            "cashflow_assessment": f"FOIR: {foir}%. AMB: Rs {avg_monthly_balance:,.0f}. Bounces: {bounce_count_6m}.",
            "strengths": [], "concerns": policy_violations,
            "policy_violations": policy_violations,
            "reason": "Declined at policy screening. Hard rules triggered: " + " | ".join(policy_violations),
            "recommendation": "Resolve policy violations before reapplying.",
            "documentation_required": rules["docs"],
            "counter_offer": None,
            "loan_type": loan_type, "applicant_name": full_name,
            "loan_amount": loan_amount, "emi_estimate": round(emi),
            "foir": foir, "ltv": ltv, "computed_rate": computed_rate,
        }
        _save(result, age, employment_type, employer_name, loan_tenure, cibil_score,
              monthly_income, itr_income, gst_turnover, dpd_30_count, dpd_60_count,
              dpd_90_count, enquiries_6m, credit_vintage_yrs, avg_monthly_balance, bounce_count_6m, ltv)
        return JSONResponse(content=result)

    # Full AI credit memo prompt
    btr = "N/A"
    if gst_turnover > 0 and avg_monthly_balance > 0:
        btr = f"{round((avg_monthly_balance * 12) / gst_turnover * 100, 1)}%"

    prompt = f"""You are a Senior Credit Manager at a leading Indian NBFC with 15+ years experience.
You follow RBI Master Directions and produce structured credit assessments like real banks do.

LOAN: {loan_type} | Rate range: {rules['rate_range'][0]}%-{rules['rate_range'][1]}% | Risk-computed rate: {computed_rate}%
Policy: Max FOIR {rules['max_foir']}% | Min CIBIL {rules['min_cibil'] if rules['min_cibil'] > 0 else 'N/A'} | Max LTV {max_ltv}% | Max Tenure {rules['max_tenure']}m | Priority Sector: {'YES' if rules['priority_sector'] else 'NO'}
Underwriting note: {rules['key_check']}

APPLICANT: {full_name}, Age {age}, {employment_type}
Employer: {employer_name or 'Not specified'} | Employer vintage: {employer_vintage_yrs}y | Business vintage: {business_vintage_yrs}y {'[BELOW 2yr min for BL]' if loan_type == 'Business Loan' and business_vintage_yrs < 2 else ''}

INCOME & CASHFLOW:
- Declared monthly income: Rs {monthly_income:,.0f} | Expenses: Rs {monthly_expenses:,.0f} | Net disposable: Rs {net_income:,.0f}
- ITR income (annual): Rs {itr_income:,.0f} {('[INCOME GAP: ' + income_gap + ']') if income_gap else ''}
- GST turnover (annual): Rs {gst_turnover:,.0f} | Banking turnover ratio: {btr}
- Avg monthly bank balance: Rs {avg_monthly_balance:,.0f}
- Salary/credit regularity: {'Regular' if sal_reg_bool else 'IRREGULAR'}
- Cheque/ECS bounces (6m): {bounce_count_6m} {'[CAUTION]' if bounce_count_6m > 1 else ''}

BUREAU:
- CIBIL: {cibil_score} | Credit vintage: {credit_vintage_yrs}y | Secured/unsecured mix: {secured_unsecured_ratio or 'N/A'}
- DPD 30+: {dpd_30_count} | DPD 60+: {dpd_60_count} | DPD 90+: {dpd_90_count}
- Write-off/settlement: {'YES' if wo_bool else 'None'} | Enquiries (6m): {enquiries_6m} {'[HIGH]' if enquiries_6m > 3 else ''}
- Existing EMI obligations: Rs {existing_emi_total:,.0f}/month

LOAN REQUEST:
- Amount: Rs {loan_amount:,.0f} | Tenure: {loan_tenure}m | Purpose: {loan_purpose}
- EMI estimate: Rs {emi:,.0f} | FOIR post-EMI: {foir}% {'[EXCEEDS LIMIT]' if foir > rules['max_foir'] else '[OK]'}
- Collateral: Rs {collateral_value:,.0f} | LTV: {str(ltv)+'%' if ltv else 'N/A'} {'[LTV BREACH]' if ltv_breach else ''}

Respond ONLY with this JSON (no other text):
{{
  "decision": "APPROVED" or "REJECTED" or "CONDITIONAL",
  "risk_level": "LOW" or "MEDIUM" or "HIGH",
  "risk_score": <0-100>,
  "approved_amount": <number or 0>,
  "recommended_interest_rate": {computed_rate},
  "processing_fee": <rupee amount>,
  "max_eligible_tenure": <months>,
  "fraud_flags": [],
  "regulatory_flags": [],
  "bureau_assessment": "<2-3 sentences on bureau quality>",
  "cashflow_assessment": "<2-3 sentences on income, banking, FOIR>",
  "strengths": ["s1","s2","s3"],
  "concerns": ["c1","c2"],
  "policy_violations": [],
  "reason": "<3-4 plain English sentences covering all key factors>",
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
        return JSONResponse({"error": "AI response parsing failed. Retry."}, status_code=500)
    except Exception as e:
        logger.error(f"Claude error: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)

    app_id = generate_app_id()
    result.update({
        "application_id": app_id, "loan_type": loan_type,
        "applicant_name": full_name, "loan_amount": loan_amount,
        "emi_estimate": round(emi), "foir": foir,
        "ltv": ltv, "computed_rate": computed_rate, "policy_violations": [],
    })
    _save(result, age, employment_type, employer_name, loan_tenure, cibil_score,
          monthly_income, itr_income, gst_turnover, dpd_30_count, dpd_60_count,
          dpd_90_count, enquiries_6m, credit_vintage_yrs, avg_monthly_balance, bounce_count_6m, ltv)
    return JSONResponse(content=result)


def _save(result, age, emp, employer, tenure, cibil, income, itr, gst,
          dpd30, dpd60, dpd90, enq, vintage, amb, bounce, ltv):
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
                counter_offer, bureau_assessment, cashflow_assessment
            ) VALUES (
                :app_id, :name, :age, :emp, :employer,
                :lt, :la, :tenure, :cibil,
                :dpd30, :dpd60, :dpd90, :enq,
                :vintage, :amb, :bounce,
                :income, :itr, :gst,
                :decision, :pviol, :risk, :score,
                :approved, :rate, :foir, :ltv, :emi,
                :fraud, :reg, :strengths, :concerns,
                :docs, :reason, :rec, :counter, :bureau, :cashflow
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
            cashflow=result.get("cashflow_assessment")
        )
        conn.close()
        logger.info(f"✅ Saved {result['application_id']}")
    except Exception as e:
        logger.error(f"❌ DB save: {e}")


@app.get("/health")
def health():
    return {"status": "ok", "service": "NBFC AI Platform v3.0", "loan_types": len(LOAN_RULES)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
