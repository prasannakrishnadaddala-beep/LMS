from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import anthropic
import os
import json

app = FastAPI(title="NBFC AI Platform")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

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

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "loan_types": list(LOAN_RULES.keys())
    })

@app.post("/analyze-loan")
async def analyze_loan(
    full_name: str = Form(...),
    age: int = Form(...),
    monthly_income: float = Form(...),
    loan_amount: float = Form(...),
    loan_tenure: int = Form(...),
    employment_type: str = Form(...),
    loan_type: str = Form(...),
    cibil_score: int = Form(...),
    existing_loans: int = Form(...),
    loan_purpose: str = Form(...),
    monthly_expenses: float = Form(...),
    collateral_value: float = Form(0),
    business_vintage: int = Form(0)
):
    rules = LOAN_RULES.get(loan_type, LOAN_RULES["Personal Loan"])
    rate_parts = rules["typical_rate"].split("-")
    rate_mid = float(rate_parts[0])
    monthly_rate = rate_mid / 100 / 12
    if monthly_rate > 0 and loan_tenure > 0:
        emi = loan_amount * monthly_rate * (1 + monthly_rate)**loan_tenure / ((1 + monthly_rate)**loan_tenure - 1)
    else:
        emi = loan_amount / loan_tenure if loan_tenure else 0

    total_obligations = emi + (existing_loans * 4500)
    foir = round((total_obligations / monthly_income) * 100, 1)
    net_income = monthly_income - monthly_expenses
    ltv = round((loan_amount / collateral_value) * 100, 1) if collateral_value > 0 else None
    max_ltv = rules.get("max_ltv")
    ltv_breach = (ltv is not None and max_ltv is not None and ltv > max_ltv)
    cibil_fail = (rules["min_cibil"] > 0 and cibil_score < rules["min_cibil"])

    prompt = f"""You are a senior NBFC credit underwriter with deep knowledge of RBI guidelines, FOIR norms, CIBIL scoring, and product-specific rules for Indian lending.

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

Apply product-specific underwriting for {loan_type}. Respond ONLY in this exact JSON:
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

    message = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        messages=[{"role": "user", "content": prompt}]
    )

    raw = message.content[0].text.strip().replace("```json","").replace("```","").strip()
    result = json.loads(raw)
    result["loan_type"] = loan_type
    result["applicant_name"] = full_name
    result["loan_amount"] = loan_amount
    result["emi_estimate"] = round(emi)
    result["foir"] = foir
    result["ltv"] = ltv
    return JSONResponse(content=result)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "NBFC AI Platform v2.0", "loan_types": len(LOAN_RULES)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
