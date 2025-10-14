import streamlit as st
import hashlib
import time


class SimpleAuthenticator:
    """
    Simple username/password authentication for Streamlit apps.
    This is a development/testing alternative to full OIDC.

    NOTE: This is NOT suitable for production use. For production,
    use proper OIDC authentication (see oidc_auth.py).
    """

    def __init__(self, users=None):
        """
        Initialize authenticator with user credentials.

        Args:
            users: Dictionary of {username: password_hash}
                   If None, uses default test credentials
        """
        if users is None:
            # Default test users (password is hashed)
            # Default credentials: admin/admin, user/password
            self.users = {
                "admin": self._hash_password("admin"),
                "user": self._hash_password("password"),
            }
        else:
            self.users = users

    def _hash_password(self, password):
        """Hash password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()

    def authenticate(self, username, password):
        """
        Verify username and password.

        Args:
            username: Username to verify
            password: Password to verify

        Returns:
            bool: True if credentials are valid
        """
        password_hash = self._hash_password(password)
        return username in self.users and self.users[username] == password_hash

    def is_authenticated(self):
        """
        Check if user is currently authenticated.

        Returns:
            bool: True if user is logged in
        """
        return st.session_state.get("authenticated", False)

    def get_user_info(self):
        """
        Get current user information.

        Returns:
            dict: User information
        """
        return {
            "username": st.session_state.get("username"),
            "authenticated": self.is_authenticated(),
            "login_time": st.session_state.get("login_time"),
        }

    def logout(self):
        """Clear authentication session."""
        st.session_state.clear()

    def login_form(self):
        """
        Display login form and handle authentication.

        Returns:
            bool: True if user successfully authenticated
        """
        st.title("🔐 Login Required")
        st.markdown("---")

        st.info("Please log in to access SAGE")

        # Create login form
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login", use_container_width=True)

            if submit:
                if self.authenticate(username, password):
                    # Set session state
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = username
                    st.session_state["login_time"] = time.time()
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error("Invalid username or password")

        st.markdown("---")
        st.caption("**Default credentials for testing:**")
        st.caption("Username: `admin` / Password: `admin`")
        st.caption("Username: `user` / Password: `password`")

        return False

    def require_auth(self):
        """
        Force authentication. Call this at the start of your app.
        Shows login form if not authenticated.

        Returns:
            bool: True if authenticated, False otherwise
        """
        if not self.is_authenticated():
            self.login_form()
            st.stop()
            return False
        return True


def create_simple_auth():
    """
    Factory function to create a simple authenticator.

    To add custom users, pass a dictionary:
    users = {
        "username1": hashlib.sha256("password1".encode()).hexdigest(),
        "username2": hashlib.sha256("password2".encode()).hexdigest(),
    }

    Returns:
        SimpleAuthenticator: Configured authenticator instance
    """
    return SimpleAuthenticator()


# Example usage
if __name__ == "__main__":
    st.set_page_config(page_title="Simple Auth Example", page_icon="🔐")

    # Create authenticator
    auth = create_simple_auth()

    # Require authentication
    auth.require_auth()

    # If we reach here, user is authenticated
    st.title("🎉 Welcome to SAGE!")

    user_info = auth.get_user_info()
    st.success(f"Logged in as: **{user_info['username']}**")

    # Show logout button
    if st.button("Logout"):
        auth.logout()
        st.rerun()

    st.markdown("---")
    st.markdown("### Your Protected Content")
    st.write("This content is only visible to authenticated users.")
