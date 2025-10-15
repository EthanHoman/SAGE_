#!/bin/bash
#
# SAGE Production Deployment Script with Nginx
# For Ubuntu 22.04 LTS / Debian-based systems
#
# Usage: sudo bash install.sh
#

set -e  # Exit on error

echo "========================================="
echo "SAGE Production Deployment"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Configuration
SAGE_USER="sage"
SAGE_GROUP="sage"
SAGE_HOME="/opt/sage"
OLLAMA_USER="ollama"
DOMAIN="sage.yourdomain.com"  # CHANGE THIS

echo "📋 Configuration:"
echo "   User: $SAGE_USER"
echo "   Install path: $SAGE_HOME"
echo "   Domain: $DOMAIN"
echo ""

read -p "Continue with installation? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

echo ""
echo "🔄 Step 1: System Updates"
apt update
apt upgrade -y

echo ""
echo "📦 Step 2: Installing Dependencies"
apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    git \
    curl \
    build-essential \
    certbot \
    python3-certbot-nginx

echo ""
echo "👤 Step 3: Creating System Users"
# Create SAGE user
if ! id "$SAGE_USER" &>/dev/null; then
    useradd -r -m -d $SAGE_HOME -s /bin/bash $SAGE_USER
    echo "✓ Created user: $SAGE_USER"
else
    echo "✓ User $SAGE_USER already exists"
fi

# Create Ollama user
if ! id "$OLLAMA_USER" &>/dev/null; then
    useradd -r -m -d /opt/ollama -s /bin/bash $OLLAMA_USER
    echo "✓ Created user: $OLLAMA_USER"
else
    echo "✓ User $OLLAMA_USER already exists"
fi

echo ""
echo "🤖 Step 4: Installing Ollama"
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.ai/install.sh | sh
    echo "✓ Ollama installed"
else
    echo "✓ Ollama already installed"
fi

echo ""
echo "📥 Step 5: Cloning SAGE Repository"
if [ ! -d "$SAGE_HOME/SAGE_" ]; then
    cd $SAGE_HOME
    sudo -u $SAGE_USER git clone https://github.com/EthanHoman/SAGE_.git
    mv SAGE_/* .
    rmdir SAGE_
    echo "✓ Repository cloned"
else
    echo "✓ Repository already exists"
    cd $SAGE_HOME
    sudo -u $SAGE_USER git pull origin main
fi

echo ""
echo "🐍 Step 6: Setting up Python Environment"
cd $SAGE_HOME
sudo -u $SAGE_USER python3 -m venv venv
sudo -u $SAGE_USER $SAGE_HOME/venv/bin/pip install --upgrade pip
sudo -u $SAGE_USER $SAGE_HOME/venv/bin/pip install -r requirements.txt

echo ""
echo "📚 Step 7: Downloading NLTK Data"
sudo -u $SAGE_USER $SAGE_HOME/venv/bin/python3 -c "import nltk; nltk.download('punkt'); nltk.download('averaged_perceptron_tagger')"

echo ""
echo "🔧 Step 8: Creating Environment File"
cat > $SAGE_HOME/.env << 'EOF'
# NASA Launchpad Credentials
# IMPORTANT: Replace these with your actual credentials
NASA_CLIENT_ID=YOUR_CLIENT_ID_HERE
NASA_CLIENT_SECRET=YOUR_CLIENT_SECRET_HERE

# Ollama Configuration
OLLAMA_HOST=http://127.0.0.1:11434
EOF

chown $SAGE_USER:$SAGE_GROUP $SAGE_HOME/.env
chmod 600 $SAGE_HOME/.env

echo "✓ Created .env file at $SAGE_HOME/.env"
echo "⚠️  IMPORTANT: Edit $SAGE_HOME/.env and add your NASA credentials!"

echo ""
echo "📂 Step 9: Creating Data Directories"
mkdir -p $SAGE_HOME/data
mkdir -p $SAGE_HOME/chroma_db
mkdir -p /opt/ollama/models
chown -R $SAGE_USER:$SAGE_GROUP $SAGE_HOME
chown -R $OLLAMA_USER:$OLLAMA_USER /opt/ollama

echo ""
echo "🔧 Step 10: Installing Systemd Services"
# Copy service files
cp deployment/systemd/sage.service /etc/systemd/system/
cp deployment/systemd/ollama.service /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

echo "✓ Service files installed"

echo ""
echo "🤖 Step 11: Starting Ollama"
systemctl enable ollama
systemctl start ollama

# Wait for Ollama to start
echo "Waiting for Ollama to be ready..."
sleep 5

# Pull models as ollama user
echo "Downloading AI models (this may take a while)..."
sudo -u $OLLAMA_USER ollama pull mistral
sudo -u $OLLAMA_USER ollama pull nomic-embed-text

echo "✓ Ollama configured and models downloaded"

echo ""
echo "🌐 Step 12: Configuring Nginx"
# Copy nginx config
cp deployment/nginx/sage.conf /etc/nginx/sites-available/sage

# Update domain in config
sed -i "s/sage.yourdomain.com/$DOMAIN/g" /etc/nginx/sites-available/sage

# Enable site
ln -sf /etc/nginx/sites-available/sage /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx config
nginx -t

echo "✓ Nginx configured"

echo ""
echo "🔒 Step 13: Setting up SSL Certificate"
echo "Choose SSL certificate option:"
echo "1) Let's Encrypt (automatic, free)"
echo "2) NASA Certificates (manual, I'll provide paths)"
echo "3) Skip for now (use HTTP only - not recommended)"
read -p "Enter choice (1-3): " ssl_choice

case $ssl_choice in
    1)
        echo "Setting up Let's Encrypt..."
        certbot --nginx -d $DOMAIN --non-interactive --agree-tos --email admin@$DOMAIN
        echo "✓ Let's Encrypt certificate installed"
        ;;
    2)
        echo ""
        echo "Please place your NASA certificates at:"
        echo "  Certificate: /etc/ssl/certs/nasa-sage.crt"
        echo "  Private Key: /etc/ssl/private/nasa-sage.key"
        echo "  CA Bundle: /etc/ssl/certs/nasa-ca-bundle.crt"
        echo ""
        echo "Then uncomment the NASA certificate lines in /etc/nginx/sites-available/sage"
        read -p "Press Enter when certificates are in place..."
        ;;
    3)
        echo "⚠️  Skipping SSL - HTTPS will not work!"
        echo "Edit /etc/nginx/sites-available/sage and comment out SSL lines"
        ;;
esac

# Restart nginx
systemctl restart nginx
echo "✓ Nginx restarted"

echo ""
echo "🚀 Step 14: Starting SAGE"
systemctl enable sage
systemctl start sage

echo ""
echo "========================================="
echo "✅ Installation Complete!"
echo "========================================="
echo ""
echo "📋 Next Steps:"
echo ""
echo "1. Edit credentials:"
echo "   sudo nano $SAGE_HOME/.env"
echo "   (Add your NASA_CLIENT_ID and NASA_CLIENT_SECRET)"
echo ""
echo "2. Update NASA Launchpad redirect URI to:"
echo "   https://$DOMAIN/callback"
echo ""
echo "3. Check service status:"
echo "   sudo systemctl status sage"
echo "   sudo systemctl status ollama"
echo "   sudo systemctl status nginx"
echo ""
echo "4. View logs:"
echo "   sudo journalctl -u sage -f"
echo "   sudo tail -f /var/log/nginx/sage-access.log"
echo ""
echo "5. Access SAGE at:"
echo "   https://$DOMAIN"
echo ""
echo "========================================="
echo "Useful Commands:"
echo "========================================="
echo "Restart SAGE:     sudo systemctl restart sage"
echo "Stop SAGE:        sudo systemctl stop sage"
echo "View SAGE logs:   sudo journalctl -u sage -f"
echo "Update code:      cd $SAGE_HOME && sudo -u $SAGE_USER git pull && sudo systemctl restart sage"
echo "Nginx reload:     sudo systemctl reload nginx"
echo ""
