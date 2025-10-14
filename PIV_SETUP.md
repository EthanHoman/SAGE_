# PIV Card Authentication Setup for SAGE

## What is PIV Authentication?

PIV (Personal Identity Verification) authentication uses your **NASA smartcard** and a **card reader** instead of typing a username/password. It's more secure because:

- ✅ Uses physical hardware (your PIV card)
- ✅ Requires PIN to unlock card
- ✅ Uses cryptographic certificates
- ✅ Cannot be phished or stolen remotely

## When to Use PIV vs NASA Launchpad OIDC

| PIV Authentication (`piv_auth.py`) | NASA Launchpad OIDC (`auth_oidc.py`) |
|-------------------------------------|--------------------------------------|
| Requires PIV card reader hardware | Browser-based login (no hardware) |
| Uses smartcard certificate | Username + password + 2FA |
| More secure (physical token) | Easier to set up |
| Best for: On-site/desktop use | Best for: Remote/laptop use |
| Works offline (with local server) | Requires internet connection |

## Requirements for PIV Authentication

### Hardware:
1. **PIV Card Reader** - USB smartcard reader device
   - Examples: Identiv SCR3310, Gemalto readers
   - Available from JSC Badge Office or IT

2. **NASA PIV Card** - Your NASA badge/smartcard
   - Must be current and not expired
   - Must have digital certificates loaded

### Software:
1. **PIV Middleware** - Software to communicate with card reader
   - Windows: Usually built-in (smart card service)
   - Mac: Install OpenSC or similar
   - Linux: Install pcscd and opensc

2. **Local Authentication Server** - Validates PIV certificates
   - Runs at `http://127.0.0.1:5001`
   - Handles certificate extraction and validation
   - You'll need to set this up or have IT set it up

3. **Private Key for JWT Signing**
   - File: `oidc-jwt.key`
   - Used to sign authentication tokens
   - Generate with: `openssl genrsa -out oidc-jwt.key 2048`

## Setup Instructions

### Step 1: Install Hardware
```bash
# Install PIV card reader
# Plug USB card reader into computer
# Insert your NASA PIV card

# Verify card is detected (Mac/Linux):
pcsc_scan

# Verify card is detected (Windows):
# Check Device Manager → Smart card readers
```

### Step 2: Install Dependencies
```bash
pip install cryptography PyJWT requests
```

### Step 3: Generate JWT Signing Key
```bash
# Generate RSA private key for JWT signing
openssl genrsa -out oidc-jwt.key 2048

# Keep this key secure - don't commit to git!
chmod 600 oidc-jwt.key
```

### Step 4: Set Up Local Auth Server
You need a local server running at `http://127.0.0.1:5001` that:
- Reads certificates from the PIV card
- Validates the certificate
- Returns user information

**Note:** This server needs to be built separately or provided by your IT department.

### Step 5: Update SAGE to Use PIV Auth

Edit `pdf-rag-python.py`:

```python
# Change this line:
from auth_oidc import create_nasa_auth
auth = create_nasa_auth(NASA_CLIENT_ID, NASA_CLIENT_SECRET)

# To this:
from piv_auth import create_piv_auth
auth = create_piv_auth(
    auth_server_url="http://127.0.0.1:5001",
    private_key_path="oidc-jwt.key",
    require_nasa_piv=True
)
```

### Step 6: Update Sidebar Display

The PIV auth returns different user info structure. Update sidebar in `pdf-rag-python.py`:

```python
with st.sidebar:
    st.markdown("### Authentication")
    user_info = auth.get_user_info()

    st.success("Authenticated via PIV Card")
    st.info(f"**User:** {user_info.get('common_name', 'Unknown')}")
    st.caption(f"Organization: {user_info.get('organization', 'Unknown')}")
    st.caption(f"Auth Method: {user_info.get('auth_method', 'PIV')}")

    if st.button("Logout", use_container_width=True):
        auth.logout()
        st.rerun()
```

## Testing PIV Authentication

1. **Start the local auth server** (port 5001)
2. **Insert PIV card** into reader
3. **Run Streamlit:**
   ```bash
   streamlit run pdf-rag-python.py
   ```
4. **Browser will prompt** for certificate - select your PIV certificate
5. **Enter PIN** when prompted
6. **SAGE should load** after successful authentication

## Troubleshooting

### Card Reader Not Detected
```bash
# Check card reader status (Mac/Linux)
pcsc_scan

# Restart smart card service (Linux)
sudo systemctl restart pcscd

# Check Windows Smart Card service
services.msc → Smart Card service → Start
```

### Certificate Not Found
- Ensure PIV card has certificates loaded
- Check with: `pkcs11-tool --list-objects` (requires opensc)
- Contact JSC Badge Office if certificates missing

### Auth Server Connection Failed
```bash
# Check if server is running
curl http://127.0.0.1:5001/verify

# If not, start the auth server (you'll need to build/obtain this)
```

### Private Key Missing
```bash
# Generate new key
openssl genrsa -out oidc-jwt.key 2048
```

## Comparison with Current Setup

**Your current SAGE setup uses:**
- `auth_oidc.py` - NASA Launchpad OIDC (web login)
- No hardware required
- Works from anywhere with internet

**Switching to PIV would give you:**
- `piv_auth.py` - PIV card authentication
- Requires card reader hardware
- More secure (physical token)
- Better for on-site/classified systems

## Recommendation

**For most use cases, stick with `auth_oidc.py` (NASA Launchpad OIDC)** unless:
- ✅ You have PIV card readers available
- ✅ Users are primarily on-site
- ✅ You need maximum security
- ✅ You have the local auth server infrastructure
- ✅ IT supports PIV authentication for your app

**Otherwise, NASA Launchpad OIDC is easier and more practical for most users.**

## Files Summary

- **`piv_auth.py`** - PIV card authentication (created for you)
- **`auth_oidc.py`** - NASA Launchpad OIDC (currently active) ⭐
- **`ignition_oidc.py`** - Original PIV for Ignition system (legacy)
- **`oidc_auth.py`** - Custom OIDC without authlib (alternative)
- **`simple_auth.py`** - Simple username/password (testing only)
