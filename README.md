# PhishLens (working name)

Status: **backend core + docs done; frontend, database, accounts not started.**

## Run the tests (works with no installs)
```
cd backend
python -m unittest discover -s app/tests -t .
```
## Run the API
```
cd backend && pip install -r requirements.txt
cp ../.env.example ../.env
uvicorn app.main:app --reload       # http://localhost:8000/api/docs
pytest                               # also runs the 5 HTTP tests
```
Try: `curl -X POST localhost:8000/api/v1/scans/url -H 'content-type: application/json' -d '{"url":"http://secure-login-paypal.tk/verify"}'`
Safe test URLs: `https://github.com`, `https://x.phishlens-test.invalid` (mock-positive, needs `ENABLE_MOCK_INTEL=true`).

## Demo script (backend-only, 3 minutes)
1. Scan `https://github.com` → SAFE, "not a guarantee" note, unknowns listed.
2. Scan `http://secure-login-paypal.tk/verify` → SUSPICIOUS; open the breakdown: brand, TLD, keyword, http.
3. Scan `https://xn--pypal-4ve.com` → PHISHING via mixed-script homograph.
4. Scan `http://192.168.1.1` → shows the scanner refuses internal targets.
5. Show a report with `explanation.source = "rules"` vs with an API key.
# cyberlens
