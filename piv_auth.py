"""
PIV Card Authentication for Streamlit Applications
Adapted for SAGE - removes Ignition-specific dependencies
Uses PIV card reader for certificate-based authentication
"""

import streamlit as st
import requests
import jwt
import base64
import datetime
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class PIVAuthConfig:
    """Configuration for PIV authentication."""
    auth_server_url: str = "http://127.0.0.1:5001"  # Local PIV authentication server
    token_lifetime: int = 3600  # 1 hour
    issuer: str = "https://sage.nasa.gov"
    private_key_path: str = "oidc-jwt.key"
    require_nasa_piv: bool = True  # Only accept NASA-issued PIV cards


class PIVAuthenticator:
    """
    PIV Card Authentication handler for Streamlit applications.

    Requires:
    - PIV card reader hardware
    - PIV card inserted
    - Local authentication server running (handles certificate validation)
    """

    def __init__(self, config: PIVAuthConfig = None):
        """
        Initialize PIV authenticator.

        Args:
            config: PIVAuthConfig instance with custom settings
        """
        self.config = config or PIVAuthConfig()
        self.logger = logging.getLogger(__name__)
        self._load_private_key()

    def _load_private_key(self):
        """Load private key for JWT signing."""
        try:
            with open(self.config.private_key_path, "rb") as f:
                self.private_key = f.read().decode()
        except FileNotFoundError:
            self.logger.warning(f"Private key file not found: {self.config.private_key_path}")
            self.private_key = None

    def extract_cert_info(self, raw_cert: str) -> Dict:
        """
        Extract user information from PIV certificate.

        Args:
            raw_cert: Base64-encoded DER certificate

        Returns:
            Dict containing certificate information
        """
        try:
            cert_der = base64.b64decode(raw_cert)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())

            # Extract Common Name (user identity)
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

            # Extract organizational info
            org_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
            org = org_attrs[0].value if org_attrs else "Unknown"

            cert_info = {
                "common_name": cn,
                "organization": org,
                "serial_number": str(cert.serial_number),
                "issuer": cert.issuer.rfc4514_string(),
                "valid_from": cert.not_valid_before,
                "valid_until": cert.not_valid_after
            }

            # Check if it's a NASA PIV card
            cert_info["is_nasa_piv"] = "NASA" in org or "NASA" in cert_info["issuer"]

            return cert_info

        except Exception as e:
            self.logger.error(f"Certificate extraction failed: {e}")
            raise ValueError(f"Invalid certificate: {str(e)}")

    def validate_certificate(self, cert_info: Dict) -> Tuple[bool, str]:
        """
        Validate certificate against business rules.

        Args:
            cert_info: Certificate information dict

        Returns:
            Tuple of (is_valid, message)
        """
        try:
            now = datetime.datetime.utcnow()

            # Check expiration
            if cert_info["valid_until"] < now:
                return False, "Certificate has expired"

            # Check not-before date
            if cert_info["valid_from"] > now:
                return False, "Certificate not yet valid"

            # Check if NASA PIV required
            if self.config.require_nasa_piv and not cert_info.get("is_nasa_piv", False):
                return False, "Only NASA PIV cards are accepted"

            return True, "Certificate valid"

        except Exception as e:
            return False, f"Validation error: {str(e)}"

    def create_jwt_token(self, cert_info: Dict) -> str:
        """
        Create JWT token from certificate information.

        Args:
            cert_info: Certificate information dict

        Returns:
            Signed JWT token string
        """
        if not self.private_key:
            raise ValueError("Private key not loaded - cannot create JWT token")

        now = datetime.datetime.utcnow()

        payload = {
            "iss": self.config.issuer,
            "sub": cert_info["common_name"],
            "preferred_username": cert_info["common_name"],
            "organization": cert_info.get("organization", "Unknown"),
            "iat": now,
            "exp": now + datetime.timedelta(seconds=self.config.token_lifetime),
            "cert_serial": cert_info["serial_number"],
            "auth_method": "PIV"
        }

        return jwt.encode(payload, self.private_key, algorithm="RS256")

    def check_authentication_server(self) -> Dict:
        """
        Check authentication status with local PIV authentication server.

        Returns:
            Dict with authentication status and user info
        """
        try:
            response = requests.get(
                f"{self.config.auth_server_url}/verify",
                timeout=5
            )
            if response.status_code == 200:
                return response.json()
            return {"authenticated": False}
        except requests.exceptions.ConnectionError:
            self.logger.error("Cannot connect to PIV authentication server. Is it running?")
            return {"authenticated": False, "error": "Auth server not available"}
        except Exception as e:
            self.logger.error(f"Auth server error: {e}")
            return {"authenticated": False, "error": str(e)}

    def is_authenticated(self) -> bool:
        """
        Check if user is currently authenticated via PIV card.

        Returns:
            True if authenticated
        """
        # Check session state first
        if st.session_state.get('piv_authenticated', False):
            # Verify token hasn't expired
            token_expiry = st.session_state.get('piv_token_expiry', 0)
            if datetime.datetime.now().timestamp() < token_expiry:
                return True

        # Check with auth server
        auth_status = self.check_authentication_server()
        if auth_status.get("authenticated", False):
            # Store in session
            st.session_state['piv_authenticated'] = True
            st.session_state['piv_user'] = auth_status.get('user', {})
            st.session_state['piv_token'] = auth_status.get('token')

            # Set expiry
            expires_in = auth_status.get('expires_in', self.config.token_lifetime)
            st.session_state['piv_token_expiry'] = (
                datetime.datetime.now() + datetime.timedelta(seconds=expires_in)
            ).timestamp()

            return True

        return False

    def get_user_info(self) -> Dict:
        """
        Get current authenticated user information.

        Returns:
            Dict containing user info from PIV card
        """
        if not self.is_authenticated():
            return {}

        user_info = st.session_state.get('piv_user', {})

        # Add PIV-specific metadata
        return {
            'authenticated': True,
            'auth_method': 'PIV',
            'common_name': user_info.get('common_name', 'Unknown'),
            'organization': user_info.get('organization', 'Unknown'),
            'cert_serial': user_info.get('cert_serial'),
            'piv_user': user_info
        }

    def logout(self):
        """Clear authentication session."""
        # Clear session state
        keys_to_clear = [
            'piv_authenticated',
            'piv_user',
            'piv_token',
            'piv_token_expiry'
        ]
        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]

        # Notify auth server
        try:
            requests.post(f"{self.config.auth_server_url}/logout", timeout=5)
        except Exception:
            pass

    def require_auth(self) -> bool:
        """
        Require PIV authentication before proceeding.
        Shows authentication UI if not authenticated.

        Returns:
            True if authenticated
        """
        if self.is_authenticated():
            return True

        # Show authentication required page
        self._show_auth_page()
        st.stop()
        return False

    def _show_auth_page(self):
        """Display PIV authentication required page."""
        st.title("🔐 PIV Card Authentication Required")
        st.markdown("---")

        st.info("**SAGE** requires PIV card authentication to access this application.")

        # Check auth server status
        auth_status = self.check_authentication_server()

        if "error" in auth_status:
            st.error(f"⚠️ Authentication Server Error: {auth_status['error']}")
            st.warning("""
            **Troubleshooting Steps:**
            1. Ensure the PIV authentication server is running
            2. Check that the server is accessible at: `{}`
            3. Verify your network connection
            """.format(self.config.auth_server_url))

        st.markdown("""
        ### Requirements

        To access this system you need:

        1. **PIV Card Reader** - Hardware device connected to your computer
        2. **NASA PIV Card** - Valid NASA-issued PIV smartcard inserted in reader
        3. **PIN** - Your PIV card PIN ready
        4. **Browser Configuration** - Client certificate authentication enabled

        ### Setup Instructions

        #### Step 1: Insert PIV Card
        - Insert your NASA PIV card into the card reader
        - Ensure the card is fully inserted and recognized

        #### Step 2: Browser Setup
        - **Chrome/Edge**: Settings → Privacy & Security → Security → Manage Certificates
        - **Firefox**: Settings → Privacy & Security → View Certificates → Your Certificates
        - Enable "Ask for certificate" when websites request it

        #### Step 3: Authenticate
        - Click the "Retry Authentication" button below
        - Select your PIV certificate when prompted
        - Enter your PIV PIN when requested
        """)

        col1, col2, col3 = st.columns([1, 1, 1])

        with col2:
            if st.button("🔄 Retry Authentication", type="primary", use_container_width=True):
                st.rerun()

        with st.expander("ℹ️ Troubleshooting", expanded=False):
            st.markdown("""
            **Common Issues:**

            • **PIV Card Not Detected**
              - Check card reader connection
              - Ensure card is fully inserted
              - Try removing and reinserting card
              - Restart card reader drivers

            • **Browser Not Prompting for Certificate**
              - Clear browser cache and cookies
              - Check browser security settings
              - Try a different browser
              - Ensure PIV middleware is installed

            • **PIN Not Working**
              - Verify you're using the correct PIN
              - Check if card is locked (too many failed attempts)
              - Contact your security office if locked

            • **Certificate Expired**
              - Contact your badge office for renewal
              - Update your PIV card

            **Support Contact:**
            - JSC Badge Office: (281) 483-5111
            - IT Support: (281) 483-4357
            """)

        st.markdown("---")
        st.caption("🔒 Secured with PKI Certificate Authentication")


def create_piv_auth(
    auth_server_url: str = "http://127.0.0.1:5001",
    private_key_path: str = "oidc-jwt.key",
    require_nasa_piv: bool = True
) -> PIVAuthenticator:
    """
    Factory function to create PIV authenticator.

    Args:
        auth_server_url: URL of local PIV authentication server
        private_key_path: Path to private key for JWT signing
        require_nasa_piv: Only accept NASA-issued PIV cards

    Returns:
        Configured PIVAuthenticator instance
    """
    config = PIVAuthConfig(
        auth_server_url=auth_server_url,
        private_key_path=private_key_path,
        require_nasa_piv=require_nasa_piv
    )
    return PIVAuthenticator(config)


# Example usage
if __name__ == "__main__":
    st.set_page_config(
        page_title="PIV Auth Example",
        page_icon="🔐"
    )

    # Create PIV authenticator
    auth = create_piv_auth()

    # Require authentication
    auth.require_auth()

    # If we reach here, user is authenticated
    st.title("🎉 Welcome!")
    st.success("Successfully authenticated via PIV card")

    # Display user information
    user_info = auth.get_user_info()

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### User Information")
        st.info(f"**Name:** {user_info.get('common_name', 'Unknown')}")
        st.text(f"Organization: {user_info.get('organization', 'Unknown')}")
        st.text(f"Auth Method: {user_info.get('auth_method', 'Unknown')}")

    with col2:
        st.markdown("### Certificate")
        if user_info.get('cert_serial'):
            st.text(f"Serial: {user_info['cert_serial']}")

    # Logout button
    with st.sidebar:
        st.markdown("### PIV Authentication")
        st.success("✅ Authenticated")

        if st.button("Logout", use_container_width=True):
            auth.logout()
            st.rerun()

    st.markdown("---")
    st.markdown("### Your Protected Content")
    st.write("This content is only accessible with valid PIV card authentication.")
