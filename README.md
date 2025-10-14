# SAGE - Safety Analysis Generation Engine

A Streamlit-based AI application for generating safety analysis documentation using RAG (Retrieval-Augmented Generation) with NASA Launchpad authentication.

## 🚀 Features

- **AI-Powered Q&A**: Ask questions about safety analysis documentation and get contextual answers
- **RAG Architecture**: Uses vector database (ChromaDB) for intelligent document retrieval
- **NASA Authentication**: Multiple authentication options:
  - NASA Launchpad OIDC (recommended)
  - PIV Card authentication
  - Simple auth (testing only)
- **Local LLM**: Powered by Ollama with Mistral model
- **Secure**: HTTPS support with SSL certificates

## 📋 Requirements

### Hardware
- Computer with sufficient RAM for LLM (8GB+ recommended)
- (Optional) PIV card reader for PIV authentication

### Software
- Python 3.9+
- Ollama (for local LLM)
- PIV card reader drivers (if using PIV auth)

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/EthanHoman/SAGE_.git
cd SAGE_
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install and Setup Ollama
```bash
# Install Ollama (https://ollama.ai)
# Then pull required models:
ollama pull mistral
ollama pull nomic-embed-text
```

### 5. Download NLTK Data
```bash
python3 -c "import nltk; nltk.download('punkt'); nltk.download('averaged_perceptron_tagger')"
```

### 6. Setup SSL Certificates
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=Texas/L=Houston/O=NASA JSC/OU=EC4/CN=localhost"
```

## 🔐 Authentication Setup

### Option 1: NASA Launchpad OIDC (Recommended)

1. Register your application at NASA Launchpad
2. Get your Client ID and Client Secret
3. Update credentials in `pdf-rag-python.py`:
```python
NASA_CLIENT_ID = "your-client-id"
NASA_CLIENT_SECRET = "your-client-secret"
```

See `AUTH_COMPARISON.md` for more details.

### Option 2: PIV Card Authentication

See `PIV_SETUP.md` for complete PIV card setup instructions.

### Option 3: Simple Auth (Testing Only)

No setup required. Default credentials:
- Username: `admin` / Password: `admin`
- Username: `user` / Password: `password`

## 🏃 Running the Application

```bash
streamlit run pdf-rag-python.py
```

The app will run at `https://localhost:5000`

**Note:** Your browser will show a security warning for the self-signed certificate. This is normal for local development.

## 📁 Project Structure

```
.
├── pdf-rag-python.py          # Main Streamlit application
├── auth_oidc.py               # NASA Launchpad OIDC auth (Authlib)
├── piv_auth.py                # PIV card authentication
├── oidc_auth.py               # Custom OIDC implementation
├── simple_auth.py             # Simple username/password auth
├── requirements.txt           # Python dependencies
├── .streamlit/
│   └── config.toml           # Streamlit configuration (port 5000, HTTPS)
├── data/                      # PDF documents for RAG
├── chroma_db/                 # Vector database (auto-generated)
├── cert.pem                   # SSL certificate
├── key.pem                    # SSL private key
├── AUTH_COMPARISON.md         # Authentication options comparison
└── PIV_SETUP.md              # PIV authentication setup guide
```

## 📚 Documentation

- **Authentication Options**: See `AUTH_COMPARISON.md`
- **PIV Setup**: See `PIV_SETUP.md`
- **Configuration**: Edit `.streamlit/config.toml` for port/SSL settings

## 🔒 Security Notes

- **Never commit credentials** to git (protected by `.gitignore`)
- **SSL certificates** are for local development only
- **Use NASA Launchpad** for production authentication
- **Keep your Client Secret secure**

## 🐛 Troubleshooting

### PDF Not Found
```bash
# Add your PDF to the data/ directory
cp your-document.pdf data/
```

### Ollama Not Running
```bash
# Start Ollama
ollama serve
```

### Authentication Errors
- Verify NASA Launchpad credentials are correct
- Check that redirect URI matches registration
- Ensure port 5000 is not blocked by firewall

### NLTK Data Missing
```bash
python3 -c "import nltk; nltk.download('punkt')"
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

Developed by JSC EC4 for NASA internal use.

## 👥 Authors

- Ethan Homan - Initial development
- JSC EC4 Team

## 🙏 Acknowledgments

- NASA Johnson Space Center
- Langchain community
- Ollama team
- Streamlit team

## 📞 Support

For issues or questions:
- GitHub Issues: https://github.com/EthanHoman/SAGE_/issues
- Email: ethan.b.homan@nasa.gov
