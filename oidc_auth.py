import streamlit as st
import requests
import secrets
import hashlib
import base64
from urllib.parse import urlencode, parse_qs, urlparse
import time
import json
import jwt


class OIDCAuthenticator:
    """
    OIDC Authentication handler for Streamlit applications.
    Uses the OIDC Debugger for testing authentication flows.
    """

    def __init__(
        self,
        client_id="your-client-id",
        client_secret=None,
        authorization_endpoint="https://oidcdebugger.com/authorize",
        token_endpoint="https://oidcdebugger.com/token",
        userinfo_endpoint=None,
        redirect_uri="http://localhost:8501",
        scope="openid profile email"
    ):
        """
        Initialize OIDC authenticator.

        Args:
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret (optional, for confidential clients)
            authorization_endpoint: OIDC authorization URL
            token_endpoint: OIDC token endpoint URL
            userinfo_endpoint: OIDC userinfo endpoint (optional)
            redirect_uri: Callback URL after authentication
            scope: Space-separated list of OAuth2 scopes
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.userinfo_endpoint = userinfo_endpoint
        self.redirect_uri = redirect_uri
        self.scope = scope

    def generate_pkce_pair(self):
        """
        Generate PKCE code verifier and challenge for secure auth flow.

        Returns:
            tuple: (code_verifier, code_challenge)
        """
        # Generate code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8')
        code_verifier = code_verifier.rstrip('=')

        # Generate code challenge (SHA256 hash of verifier)
        code_challenge = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(code_challenge).decode('utf-8')
        code_challenge = code_challenge.rstrip('=')

        return code_verifier, code_challenge

    def get_authorization_url(self):
        """
        Generate the OIDC authorization URL.

        Returns:
            str: Full authorization URL with parameters
        """
        # Generate state for CSRF protection
        state = secrets.token_urlsafe(32)

        # Generate PKCE parameters
        code_verifier, code_challenge = self.generate_pkce_pair()

        # Store in session state
        st.session_state['oauth_state'] = state
        st.session_state['code_verifier'] = code_verifier

        # Build authorization URL parameters
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'scope': self.scope,
            'redirect_uri': self.redirect_uri,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'response_mode': 'form_post'
        }

        auth_url = f"{self.authorization_endpoint}?{urlencode(params)}"
        return auth_url

    def exchange_code_for_token(self, auth_code):
        """
        Exchange authorization code for access token.

        Args:
            auth_code: Authorization code from callback

        Returns:
            dict: Token response containing access_token, id_token, etc.
        """
        code_verifier = st.session_state.get('code_verifier')

        token_data = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'code_verifier': code_verifier
        }

        # Add client_secret if provided (for confidential clients)
        if self.client_secret:
            token_data['client_secret'] = self.client_secret

        try:
            response = requests.post(
                self.token_endpoint,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            st.error(f"Token exchange failed: {str(e)}")
            if hasattr(e.response, 'text'):
                st.error(f"Details: {e.response.text}")
            return None

    def validate_state(self, received_state):
        """
        Validate the state parameter to prevent CSRF attacks.

        Args:
            received_state: State value from callback

        Returns:
            bool: True if state is valid
        """
        stored_state = st.session_state.get('oauth_state')
        return stored_state and stored_state == received_state

    def is_authenticated(self):
        """
        Check if user is currently authenticated.

        Returns:
            bool: True if user has valid access token
        """
        if 'access_token' not in st.session_state:
            return False

        # Check if token is expired
        token_expiry = st.session_state.get('token_expiry', 0)
        return time.time() < token_expiry

    def decode_id_token(self, id_token):
        """
        Decode the ID token to extract user claims (without signature verification for now).

        Args:
            id_token: JWT ID token from OIDC provider

        Returns:
            dict: Decoded token claims
        """
        try:
            # Decode without verification (for development)
            # In production, you should verify the signature
            decoded = jwt.decode(id_token, options={"verify_signature": False})
            return decoded
        except Exception as e:
            st.error(f"Failed to decode ID token: {str(e)}")
            return {}

    def fetch_userinfo(self, access_token):
        """
        Fetch user information from the userinfo endpoint.

        Args:
            access_token: Access token from token response

        Returns:
            dict: User information from userinfo endpoint
        """
        if not self.userinfo_endpoint:
            return {}

        try:
            response = requests.get(
                self.userinfo_endpoint,
                headers={'Authorization': f'Bearer {access_token}'}
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            st.warning(f"Could not fetch userinfo: {str(e)}")
            return {}

    def get_user_info(self):
        """
        Retrieve user information from stored token claims.

        Returns NASA-specific user attributes:
        - UUPIC: NASA Employee Number
        - AgencyUID: NASA Agency UID
        - nasaPrimaryEmail: NASA Email
        - groups: User's role groups (filtered to SAGE-specific groups)

        Returns:
            dict: User information (email, name, NASA attributes, groups, etc.)
        """
        return st.session_state.get('user_info', {})

    def logout(self):
        """Clear authentication session data."""
        keys_to_clear = [
            'access_token',
            'id_token',
            'user_info',
            'token_expiry',
            'oauth_state',
            'code_verifier'
        ]
        for key in keys_to_clear:
            if key in st.session_state:
                del st.session_state[key]

    def require_auth(self):
        """
        Force OIDC authentication. Call this at the start of your app.
        Shows login UI if not authenticated, otherwise allows app to continue.

        Returns:
            bool: True if authenticated, False otherwise
        """
        # Check for callback parameters in URL
        query_params = st.query_params

        # Handle authorization callback
        if 'code' in query_params and 'state' in query_params:
            auth_code = query_params['code']
            state = query_params['state']

            # Validate state
            if not self.validate_state(state):
                st.error("Invalid state parameter. Possible CSRF attack.")
                st.stop()

            # Exchange code for token
            token_response = self.exchange_code_for_token(auth_code)

            if token_response and 'access_token' in token_response:
                # Store tokens
                access_token = token_response['access_token']
                id_token = token_response.get('id_token')

                st.session_state['access_token'] = access_token
                st.session_state['id_token'] = id_token

                # Calculate token expiry
                expires_in = token_response.get('expires_in', 3600)
                st.session_state['token_expiry'] = time.time() + expires_in

                # Extract user information from ID token and userinfo endpoint
                user_info = {
                    'authenticated': True,
                    'timestamp': time.time()
                }

                # Decode ID token to get claims
                if id_token:
                    token_claims = self.decode_id_token(id_token)
                    user_info.update(token_claims)

                # Fetch additional user info from userinfo endpoint
                userinfo_data = self.fetch_userinfo(access_token)
                user_info.update(userinfo_data)

                # Extract NASA-specific attributes
                nasa_attrs = {}
                if 'UUPIC' in user_info:
                    nasa_attrs['employee_number'] = user_info['UUPIC']
                if 'AgencyUID' in user_info:
                    nasa_attrs['agency_uid'] = user_info['AgencyUID']
                if 'nasaPrimaryEmail' in user_info:
                    nasa_attrs['email'] = user_info['nasaPrimaryEmail']

                # Extract and filter groups (look for SAGE-specific groups)
                groups = user_info.get('groups', [])
                if isinstance(groups, str):
                    groups = [groups]

                # Filter for SAGE Developer groups (CN=ND-GG-272044-*)
                sage_groups = [g for g in groups if 'ND-GG-272044' in g]
                nasa_attrs['groups'] = groups
                nasa_attrs['sage_groups'] = sage_groups

                # Check if user has required SAGE Developer role
                has_sage_access = any('SAGE-Developer' in g for g in sage_groups)
                nasa_attrs['has_sage_access'] = has_sage_access

                user_info['nasa'] = nasa_attrs

                # Store user info in session
                st.session_state['user_info'] = user_info

                # Clear query parameters
                st.query_params.clear()
                st.rerun()

        # Check if already authenticated
        if self.is_authenticated():
            return True

        # Show login screen
        st.title("🔐 Authentication Required")
        st.markdown("---")
        st.info("This application requires OIDC authentication to continue.")

        st.markdown("""
        ### About OIDC Authentication
        This app uses OpenID Connect (OIDC) for secure authentication.
        You'll be redirected to the authentication provider to log in.
        """)

        # Generate authorization URL
        auth_url = self.get_authorization_url()

        # Show login button
        st.markdown("### Ready to proceed?")
        st.link_button(
            "🚀 Login with OIDC",
            auth_url,
            use_container_width=True
        )

        st.markdown("---")
        st.caption("Powered by OpenID Connect")

        # Stop execution until authenticated
        st.stop()
        return False


def create_auth_wrapper():
    """
    Factory function to create and configure OIDC authenticator.
    Configured for NASA Launchpad ADFS Production environment.

    Configuration Details:
    - Integration: 34478-JSC-ADFS-PROD-OIDC-localhost:5000/callback
    - NAMS Workflow: 272044 (SAGE Developer)
    - Groups: CN=ND-GG-272044-SAGE-Developer
    - User Attributes: UUPIC, AgencyUID, nasaPrimaryEmail, groups

    IMPORTANT: Update the client_id and client_secret below with the actual values
    provided by NASA Launchpad for your integration.

    NOTE: The redirect_uri must match what's registered in Launchpad.
    Currently set to http://localhost:8501 but your registration shows https://localhost:5000/callback
    You may need to update your Launchpad registration or change the redirect_uri below.

    Returns:
        OIDCAuthenticator: Configured authenticator instance
    """
    return OIDCAuthenticator(
        client_id="YOUR_CLIENT_ID_HERE",  # TODO: Replace with your actual Client ID from Launchpad
        client_secret="YOUR_CLIENT_SECRET_HERE",  # TODO: Replace with your actual Client Secret from Launchpad
        authorization_endpoint="https://authfs.launchpad.nasa.gov/adfs/oauth2/authorize/",
        token_endpoint="https://authfs.launchpad.nasa.gov/adfs/oauth2/token/",
        userinfo_endpoint="https://authfs.launchpad.nasa.gov/adfs/userinfo",
        redirect_uri="https://localhost:5000",  # Base URL - Streamlit handles query params
        scope="openid profile email"
    )


# Example usage in your Streamlit app:
if __name__ == "__main__":
    st.set_page_config(page_title="OIDC Auth Example", page_icon="🔐")

    # Create authenticator
    auth = create_auth_wrapper()

    # Require authentication - this will show login if not authenticated
    auth.require_auth()

    # If we reach here, user is authenticated
    st.title("🎉 Welcome - You're Authenticated!")

    user_info = auth.get_user_info()
    st.success(f"Successfully authenticated at {time.ctime(user_info.get('timestamp', 0))}")

    # Show logout button
    if st.button("Logout"):
        auth.logout()
        st.rerun()

    st.markdown("---")
    st.markdown("### Your Protected Content Goes Here")
    st.write("This content is only visible to authenticated users.")
