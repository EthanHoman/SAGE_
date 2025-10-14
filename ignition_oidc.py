import streamlit as st
import requests
import jwt
import base64
import datetime
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import Dict, Optional
from dataclasses import dataclass

@dataclass
class AuthConfig:
    """Configuration for PIV authentication."""
    auth_server_url: str = "http://127.0.0.1:5001"
    token_lifetime: int = 3600
    issuer: str = "https://js-ec4-32-ignit.ndc.nasa.gov"
    private_key_path: str = "oidc-jwt.key"

class PIVAuth:
    """PIV Authentication handler for Streamlit applications."""
    
    def __init__(self, config: AuthConfig = None):
        self.config = config or AuthConfig()
        self.logger = logging.getLogger(__name__)
        self._load_private_key()
    
    def _load_private_key(self):
        """Load private key for JWT signing."""
        try:
            with open(self.config.private_key_path, "rb") as f:
                self.private_key = f.read().decode()
        except FileNotFoundError:
            self.logger.error(f"Private key file not found: {self.config.private_key_path}")
            self.private_key = None
    
    def extract_cert_info(self, raw_cert: str) -> Dict:
        """Extract user information from PIV certificate."""
        try:
            cert_der = base64.b64decode(raw_cert)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            
            return {
                "common_name": cn,
                "serial_number": str(cert.serial_number),
                "issuer": cert.issuer.rfc4514_string(),
                "valid_from": cert.not_valid_before,
                "valid_until": cert.not_valid_after
            }
            
        except Exception as e:
            self.logger.error(f"Certificate extraction failed: {e}")
            raise ValueError(f"Invalid certificate: {str(e)}")
    
    def validate_certificate(self, cert_info: Dict) -> tuple[bool, str]:
        """Validate certificate against business rules."""
        try:
            now = datetime.datetime.utcnow()
            
            if cert_info["valid_until"] < now:
                return False, "Certificate has expired"
            
            if cert_info["valid_from"] > now:
                return False, "Certificate not yet valid"
            
            # Add additional validation logic here
            return True, "Certificate valid"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def create_jwt_token(self, cert_info: Dict) -> str:
        """Create JWT token from certificate information."""
        if not self.private_key:
            raise ValueError("Private key not loaded")
            
        now = datetime.datetime.utcnow()
        
        payload = {
            "iss": self.config.issuer,
            "sub": cert_info["common_name"],
            "preferred_username": cert_info["common_name"],
            "iat": now,
            "exp": now + datetime.timedelta(seconds=self.config.token_lifetime),
            "cert_serial": cert_info["serial_number"]
        }
        
        return jwt.encode(payload, self.private_key, algorithm="RS256")
    
    def check_authentication_server(self) -> Dict:
        """Check authentication status with backend server."""
        try:
            response = requests.get(
                f"{self.config.auth_server_url}/verify",
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
            return {"authenticated": False}
        except Exception as e:
            self.logger.error(f"Auth server error: {e}")
            return {"authenticated": False}
    
    def is_authenticated(self) -> bool:
        """Check if user is currently authenticated."""
        # Check session state
        if st.session_state.get('piv_authenticated', False):
            return True
        
        # Check with auth server
        auth_status = self.check_authentication_server()
        if auth_status.get("authenticated", False):
            # Store in session
            st.session_state['piv_authenticated'] = True
            st.session_state['piv_user'] = auth_status.get('user')
            st.session_state['piv_token'] = auth_status.get('token')
            return True
        
        return False
    
    def get_current_user(self) -> str:
        """Get current authenticated user."""
        return st.session_state.get('piv_user', 'Unknown')
    
    def require_authentication(self):
        """Require PIV authentication - shows auth page if not authenticated."""
        if not self.is_authenticated():
            self.show_authentication_page()
            st.stop()
    
    def show_authentication_page(self):
        """Display PIV authentication required page."""
        st.set_page_config(page_title="Authentication Required", page_icon="🔐")
        
        st.markdown("""
        <style>
        .auth-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            min-height: 60vh;
            text-align: center;
        }
        .auth-title {
            color: #e74c3c;
            font-size: 2.5rem;
            margin-bottom: 1rem;
        }
        .auth-subtitle {
            color: #34495e;
            font-size: 1.2rem;
            margin-bottom: 2rem;
        }
        </style>
        """, unsafe_allow_html=True)
        
        with st.container():
            col1, col2, col3 = st.columns([1, 2, 1])
            
            with col2:
                st.markdown('<div class="auth-container">', unsafe_allow_html=True)
                st.markdown('<h1 class="auth-title">🔐 PIV Authentication Required</h1>', unsafe_allow_html=True)
                st.markdown('<p class="auth-subtitle">This application requires PIV certificate authentication</p>', unsafe_allow_html=True)
                
                st.info("""
                **To access this system:**
                1. Ensure your PIV card is inserted
                2. Configure your browser for client certificate authentication  
                3. Click retry below
                """)
                
                col_a, col_b, col_c = st.columns([1, 1, 1])
                
                with col_b:
                    if st.button("🔄 Retry Authentication", type="primary", use_container_width=True):
                        st.rerun()
                
                with st.expander("ℹ️ Need Help?", expanded=False):
                    st.markdown("""
                    **Common Issues:**
                    
                    • **PIV Card Issues**: Ensure card is properly inserted and reader is connected
                    • **Browser Issues**: Enable client certificates, clear cache, try different browser
                    • **Access Issues**: Contact your administrator to verify authorization
                    
                    **Support Contact:**
                    - Email: support@nasa.gov
                    - Phone: (XXX) XXX-XXXX
                    """)
                
                st.markdown('</div>', unsafe_allow_html=True)
    
    def show_user_sidebar(self, show_logout: bool = True):
        """Display user information and controls in sidebar."""
        if not self.is_authenticated():
            return
        
        with st.sidebar:
            user = self.get_current_user()
            st.success(f"✅ Authenticated: {user}")
            
            if show_logout:
                if st.button("🚪 Logout", use_container_width=True):
                    self.logout()
            
            st.divider()
            
            with st.expander("🔒 Security Info"):
                st.text("• PIV authentication active")
                st.text("• Session secured")
                st.text("• Actions logged")
                
                # Show token expiry if available
                token = st.session_state.get('piv_token')
                if token:
                    try:
                        payload = jwt.decode(token, options={"verify_signature": False})
                        exp_time = datetime.datetime.fromtimestamp(payload.get('exp', 0))
                        st.text(f"• Token expires: {exp_time.strftime('%H:%M:%S')}")
                    except:
                        pass
    
    def logout(self):
        """Clear authentication session."""
        # Clear session state
        keys_to_clear = ['piv_authenticated', 'piv_user', 'piv_token']
        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]
        
        # Notify auth server
        try:
            requests.post(f"{self.config.auth_server_url}/logout", timeout=5)
        except:
            pass
        
        st.success("Logged out successfully")
        st.rerun()
    
    def log_user_action(self, action: str, details: str = ""):
        """Log user actions for audit purposes."""
        user = self.get_current_user()
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"[{timestamp}] User: {user} | Action: {action}"
        if details:
            log_entry += f" | Details: {details}"
        
        self.logger.info(log_entry)

# Factory function for easy instantiation
def create_piv_auth(auth_server_url: str = "http://127.0.0.1:5001",
                   private_key_path: str = "oidc-jwt.key") -> PIVAuth:
    """Create PIV authentication instance with custom configuration."""
    config = AuthConfig(
        auth_server_url=auth_server_url,
        private_key_path=private_key_path
    )
    return PIVAuth(config)

# Decorator function for protecting Streamlit functions
def piv_protected(piv_auth_instance: PIVAuth):
    """Decorator to protect functions with PIV authentication."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Require authentication
            piv_auth_instance.require_authentication()
            
            # Show user info in sidebar
            piv_auth_instance.show_user_sidebar()
            
            # Call the original function
            return func(*args, **kwargs)
        return wrapper
    return decorator