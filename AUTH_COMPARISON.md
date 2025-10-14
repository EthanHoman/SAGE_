# Authentication Implementation Comparison

## Available Authentication Modules

### 1. `auth_oidc.py` ⭐ **RECOMMENDED - Production Ready**

**Uses:** Authlib (professional OAuth2/OIDC library)

**Advantages:**
- ✅ Industry-standard implementation
- ✅ Proper JWT signature verification
- ✅ Automatic token refresh support
- ✅ PKCE implementation validated
- ✅ Better security practices
- ✅ Maintained by security experts
- ✅ Production-ready
- ✅ Fewer bugs and edge cases

**Best for:**
- Production deployment
- NASA Launchpad integration
- Maximum security requirements
- Long-term maintenance

**Configuration:**
```python
from auth_oidc import create_nasa_auth

auth = create_nasa_auth(
    client_id="YOUR_CLIENT_ID",
    client_secret="YOUR_CLIENT_SECRET"
)
```

---

### 2. `oidc_auth.py` - Custom OIDC Implementation

**Uses:** Manual OAuth2/OIDC implementation with PyJWT

**Advantages:**
- ✅ No external OAuth library dependency
- ✅ Full control over flow
- ✅ Educational - see how OAuth works
- ✅ Lightweight

**Disadvantages:**
- ⚠️ Manual token verification
- ⚠️ More potential for bugs
- ⚠️ Less secure (no signature verification in current implementation)
- ⚠️ More code to maintain

**Best for:**
- Learning OAuth2/OIDC
- Environments where authlib cannot be installed
- Maximum customization needs

---

### 3. `simple_auth.py` - Simple Username/Password

**Uses:** Basic username/password with SHA-256 hashing

**Advantages:**
- ✅ No external services needed
- ✅ Works immediately
- ✅ Perfect for local testing
- ✅ No network dependencies

**Disadvantages:**
- ❌ Not suitable for production
- ❌ No real user management
- ❌ Not integrated with NASA systems

**Best for:**
- Local development
- Testing without NASA credentials
- Demo purposes

**Default credentials:**
- Username: `admin` / Password: `admin`
- Username: `user` / Password: `password`

---

## Current Configuration

Your `pdf-rag-python.py` is now configured to use **`auth_oidc.py`** (Authlib implementation).

To switch implementations, change the import:

```python
# Use Authlib (recommended)
from auth_oidc import create_nasa_auth
auth = create_nasa_auth(NASA_CLIENT_ID, NASA_CLIENT_SECRET)

# OR use custom OIDC
from oidc_auth import create_auth_wrapper
auth = create_auth_wrapper()

# OR use simple auth for testing
from simple_auth import create_simple_auth
auth = create_simple_auth()
```

---

## NASA Launchpad Configuration

All OIDC implementations are pre-configured with:

- **Authorization Endpoint:** `https://authfs.launchpad.nasa.gov/adfs/oauth2/authorize/`
- **Token Endpoint:** `https://authfs.launchpad.nasa.gov/adfs/oauth2/token/`
- **Userinfo Endpoint:** `https://authfs.launchpad.nasa.gov/adfs/userinfo`
- **Redirect URI:** `https://localhost:5000`
- **Integration:** 34478-JSC-ADFS-PROD-OIDC
- **NAMS Workflow:** 272044 (SAGE Developer)

---

## NASA User Attributes Extracted

All implementations extract these NASA-specific attributes:

- **UUPIC** → Employee Number
- **AgencyUID** → NASA Agency UID
- **nasaPrimaryEmail** → NASA Email Address
- **groups** → Active Directory groups
- **SAGE Groups** → Filtered `CN=ND-GG-272044-*` groups
- **SAGE Roles** → Extracted role names
- **has_sage_access** → Boolean flag for SAGE Developer role

Access in your app:
```python
user_info = auth.get_user_info()
nasa_info = user_info['nasa']

print(nasa_info['email'])
print(nasa_info['employee_number'])
print(nasa_info['has_sage_access'])
print(nasa_info['sage_roles'])
```

---

## Recommendation

**Use `auth_oidc.py` for production** - it's built on Authlib, which is:
- Battle-tested by thousands of applications
- Maintained by security experts
- Implements all OAuth2/OIDC specifications correctly
- Provides better error handling and security

Switch to `simple_auth.py` only for quick local testing without NASA credentials.
