# Streamlit OAuth/OIDC Known Issue

## Problem

Streamlit has a **known limitation** with OAuth/OIDC flows that causes session state to be lost during redirects. This results in the "invalid state parameter" CSRF error.

## Why This Happens

1. User clicks "Login with NASA Launchpad"
2. Browser redirects to NASA Launchpad
3. User authenticates
4. NASA Launchpad redirects back to `https://localhost:5000/callback?code=...&state=...`
5. **Streamlit reinitializes and loses session state**
6. OAuth state validation fails because stored state is gone

This is a fundamental issue with how Streamlit handles sessions across page reloads/redirects.

## Attempted Workarounds

We tried several approaches:
1. ✅ Storing state in `st.session_state` - **Fails** (session lost on redirect)
2. ✅ Storing state in `st.query_params` - **Fails** (cleared by Streamlit)
3. ✅ Encoding state in redirect URI - **Fails** (NASA Launchpad must match exact registered URI)
4. ❌ Browser cookies - **Not supported** natively in Streamlit
5. ❌ File-based session - **Complex** and not ideal for multi-user

## Solutions

### Option 1: Use Simple Auth (Quick Fix)

For development and testing, use the simple username/password auth:

```python
# In pdf-rag-python.py, change:
from simple_auth import create_simple_auth
auth = create_simple_auth()
```

Remove SSL requirement in `.streamlit/config.toml`:
```toml
[server]
port = 5000
# Comment out:
# sslCertFile = "cert.pem"
# sslKeyFile = "key.pem"
```

**Pros:** Works immediately, no setup needed
**Cons:** Not production-ready, no real NASA authentication

---

### Option 2: Deploy with Flask/FastAPI (Production)

For production, use a proper web framework:

**Flask with Flask-OIDC:**
```python
from flask import Flask
from flask_oidc import OpenIDConnect

app = Flask(__name__)
oidc = OpenIDConnect(app)

@app.route('/')
@oidc.require_login
def index():
    # Render Streamlit or call SAGE backend
    pass
```

**FastAPI with Authlib:**
```python
from fastapi import FastAPI
from authlib.integrations.starlette_client import OAuth

app = FastAPI()
oauth = OAuth()
# Configure NASA Launchpad
```

**Pros:** Proper session management, production-ready
**Cons:** More complex setup, not pure Streamlit

---

### Option 3: Streamlit + Reverse Proxy

Use Apache or Nginx with mod_auth_openidc to handle authentication:

```nginx
# Nginx handles OIDC
location / {
    auth_request /oauth2/auth;
    proxy_pass http://localhost:8501;  # Streamlit
}
```

**Pros:** Separates auth from app, works with any backend
**Cons:** Requires infrastructure setup

---

### Option 4: Use PIV Card Authentication

If you have PIV card readers deployed:

```python
from piv_auth import create_piv_auth
auth = create_piv_auth()
```

**Pros:** More secure, no OAuth redirect issues
**Cons:** Requires PIV card reader hardware and local auth server

---

### Option 5: Streamlit Community Cloud

Deploy to Streamlit Community Cloud which has better session handling:

```bash
streamlit run pdf-rag-python.py --server.enableXsrfProtection=false
```

**Note:** This is NOT recommended for security-sensitive apps.

---

## Recommended Approach

### For Development/Testing:
Use **`simple_auth.py`** - it's fast and works immediately.

### For Production:
Use **Flask/FastAPI wrapper** around your Streamlit app, or use **Apache/Nginx reverse proxy** with mod_auth_openidc.

### For NASA Internal Deployment:
Use **PIV card authentication** if infrastructure supports it, or work with NASA IT to deploy behind an authentication proxy.

---

## Why Not Fix Streamlit?

This is a known Streamlit architectural limitation. Session state is tied to WebSocket connections, which break during OAuth redirects. The Streamlit team is aware but hasn't prioritized this for OAuth use cases since Streamlit is primarily designed for data apps, not authentication-heavy web apps.

**GitHub Issues:**
- https://github.com/streamlit/streamlit/issues/4064
- https://github.com/streamlit/streamlit/issues/4832

---

## What We've Learned

**Streamlit is great for:**
- Data dashboards
- ML model demos
- Internal tools with simple auth
- Rapid prototyping

**Streamlit struggles with:**
- OAuth/OIDC flows
- Complex session management
- Multi-step redirects
- Enterprise SSO integration

For SAGE, we recommend:
1. **Short-term:** Use `simple_auth` for development
2. **Long-term:** Deploy behind NASA's authentication proxy or use Flask wrapper

---

## Current Status

The code in `auth_oidc.py` implements a workaround by encoding state in the redirect URI, but this **requires updating your NASA Launchpad registration** to include the state parameter in the redirect URI, which may not be possible.

**For now, use `simple_auth.py` until you can deploy with proper session management.**
