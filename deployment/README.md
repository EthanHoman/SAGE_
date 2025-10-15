# SAGE Production Deployment with Nginx

Complete production deployment guide for SAGE on your own server.

## Architecture

```
Internet → Nginx (Port 443/HTTPS) → Streamlit (Port 8501/Internal) → Ollama (Port 11434/Internal)
                                          ↓
                                      ChromaDB (Local Storage)
```

## Quick Start (Automated)

### Prerequisites
- Ubuntu 22.04 LTS or Debian-based Linux server
- Root/sudo access
- Domain name pointing to your server (or public IP)
- NASA Launchpad Client ID and Secret

### One-Command Install

```bash
# 1. SSH into your server
ssh user@your-server

# 2. Clone the repository
git clone https://github.com/EthanHoman/SAGE_.git
cd SAGE_

# 3. Run the installer
sudo bash deployment/install.sh
```

The installer will:
- ✅ Install all dependencies (Python, Nginx, Ollama, etc.)
- ✅ Create system users
- ✅ Clone and set up SAGE
- ✅ Configure Nginx reverse proxy
- ✅ Set up SSL certificates (Let's Encrypt or NASA)
- ✅ Install systemd services
- ✅ Download AI models
- ✅ Start everything automatically

### Post-Installation

1. **Add NASA Credentials:**
   ```bash
   sudo nano /opt/sage/.env
   ```
   Replace:
   ```
   NASA_CLIENT_ID=your-actual-client-id
   NASA_CLIENT_SECRET=your-actual-client-secret
   ```

2. **Restart SAGE:**
   ```bash
   sudo systemctl restart sage
   ```

3. **Update NASA Launchpad Redirect URI:**
   - Go to NASA Launchpad
   - Update redirect URI to: `https://your-domain.com/callback`

4. **Access SAGE:**
   - Open browser: `https://your-domain.com`

---

## Manual Installation

If you prefer step-by-step control:

### Step 1: Server Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv nginx git curl build-essential certbot python3-certbot-nginx
```

### Step 2: Create Users

```bash
# Create SAGE user
sudo useradd -r -m -d /opt/sage -s /bin/bash sage

# Create Ollama user
sudo useradd -r -m -d /opt/ollama -s /bin/bash ollama
```

### Step 3: Install Ollama

```bash
curl -fsSL https://ollama.ai/install.sh | sh
```

### Step 4: Deploy SAGE

```bash
# Switch to sage user
sudo -u sage -i

# Clone repository
cd /opt/sage
git clone https://github.com/EthanHoman/SAGE_.git .

# Create Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Download NLTK data
python3 -c "import nltk; nltk.download('punkt'); nltk.download('averaged_perceptron_tagger')"

# Create environment file
cat > .env << EOF
NASA_CLIENT_ID=your-client-id
NASA_CLIENT_SECRET=your-client-secret
OLLAMA_HOST=http://127.0.0.1:11434
EOF
chmod 600 .env

# Exit sage user
exit
```

### Step 5: Configure Systemd Services

```bash
# Install Ollama service
sudo cp /opt/sage/deployment/systemd/ollama.service /etc/systemd/system/
sudo systemctl enable ollama
sudo systemctl start ollama

# Download models
sudo -u ollama ollama pull mistral
sudo -u ollama ollama pull nomic-embed-text

# Install SAGE service
sudo cp /opt/sage/deployment/systemd/sage.service /etc/systemd/system/
sudo systemctl enable sage
sudo systemctl start sage
```

### Step 6: Configure Nginx

```bash
# Copy configuration
sudo cp /opt/sage/deployment/nginx/sage.conf /etc/nginx/sites-available/sage

# Update domain (replace 'sage.yourdomain.com' with your actual domain)
sudo nano /etc/nginx/sites-available/sage

# Enable site
sudo ln -s /etc/nginx/sites-available/sage /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx
```

### Step 7: Set Up SSL

**Option A: Let's Encrypt (Automatic)**
```bash
sudo certbot --nginx -d your-domain.com
```

**Option B: NASA Certificates (Manual)**
```bash
# Place your certificates
sudo cp nasa-sage.crt /etc/ssl/certs/
sudo cp nasa-sage.key /etc/ssl/private/
sudo chmod 600 /etc/ssl/private/nasa-sage.key

# Update Nginx config to use NASA certs
sudo nano /etc/nginx/sites-available/sage
# Uncomment the NASA certificate lines
```

---

## Configuration Files

### Nginx Configuration
Location: `/etc/nginx/sites-available/sage`

Key features:
- HTTP to HTTPS redirect
- WebSocket support for Streamlit
- SSL/TLS configuration
- Security headers
- Health check endpoint
- Long timeouts for AI queries

### Systemd Services

**SAGE Service:** `/etc/systemd/system/sage.service`
- Runs as `sage` user
- Auto-restart on failure
- Loads credentials from `/opt/sage/.env`

**Ollama Service:** `/etc/systemd/system/ollama.service`
- Runs as `ollama` user
- Manages AI models
- Internal port 11434

### Environment Variables

Location: `/opt/sage/.env`

```bash
NASA_CLIENT_ID=your-client-id
NASA_CLIENT_SECRET=your-client-secret
OLLAMA_HOST=http://127.0.0.1:11434
```

---

## Management Commands

### Service Control

```bash
# SAGE
sudo systemctl status sage        # Check status
sudo systemctl restart sage       # Restart application
sudo systemctl stop sage          # Stop application
sudo systemctl start sage         # Start application
sudo journalctl -u sage -f        # View live logs

# Ollama
sudo systemctl status ollama
sudo systemctl restart ollama

# Nginx
sudo systemctl status nginx
sudo systemctl reload nginx       # Reload config without downtime
sudo systemctl restart nginx      # Full restart
```

### Logs

```bash
# SAGE application logs
sudo journalctl -u sage -f
sudo journalctl -u sage --since "1 hour ago"

# Nginx access logs
sudo tail -f /var/log/nginx/sage-access.log

# Nginx error logs
sudo tail -f /var/log/nginx/sage-error.log

# Ollama logs
sudo journalctl -u ollama -f
```

### Updates

```bash
# Update SAGE code
cd /opt/sage
sudo -u sage git pull origin main
sudo systemctl restart sage

# Update Ollama models
sudo -u ollama ollama pull mistral
sudo -u ollama ollama pull nomic-embed-text
sudo systemctl restart sage
```

---

## Troubleshooting

### SAGE Won't Start

```bash
# Check logs
sudo journalctl -u sage -n 50

# Common issues:
# 1. Missing credentials - edit /opt/sage/.env
# 2. Ollama not running - sudo systemctl start ollama
# 3. Port conflict - check if 8501 is in use
```

### Nginx Errors

```bash
# Test configuration
sudo nginx -t

# Check error log
sudo tail -f /var/log/nginx/sage-error.log

# Common issues:
# 1. SSL certificate paths wrong
# 2. Port 443 already in use
# 3. Firewall blocking
```

### Can't Access SAGE

```bash
# Check if services are running
sudo systemctl status sage
sudo systemctl status nginx

# Check firewall
sudo ufw status
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp

# Test locally
curl http://localhost:8501/health
curl https://your-domain.com/health
```

### OAuth/Authentication Issues

```bash
# Verify NASA Launchpad redirect URI matches:
# https://your-domain.com/callback

# Check credentials in /opt/sage/.env
sudo cat /opt/sage/.env

# View authentication logs
sudo journalctl -u sage | grep -i "auth\|oidc\|nasa"
```

---

## Security Hardening

### Firewall

```bash
# Install UFW if not present
sudo apt install ufw

# Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

### SSL Certificate Auto-Renewal

```bash
# Let's Encrypt auto-renewal (already configured if using certbot)
sudo systemctl status certbot.timer

# Test renewal
sudo certbot renew --dry-run
```

### File Permissions

```bash
# Ensure proper ownership
sudo chown -R sage:sage /opt/sage
sudo chmod 600 /opt/sage/.env

# Protect SSL keys
sudo chmod 600 /etc/ssl/private/*.key
```

---

## Monitoring

### Health Checks

```bash
# Check if SAGE is responding
curl https://your-domain.com/health

# Should return: "SAGE is healthy"
```

### Resource Usage

```bash
# CPU and memory
top
htop

# Disk usage
df -h
du -sh /opt/sage/*

# Check model size
du -sh /opt/ollama/models
```

---

## Backup

### What to Backup

```bash
# 1. SAGE configuration
sudo tar -czf sage-config-backup.tar.gz /opt/sage/.env /opt/sage/.streamlit

# 2. Vector database
sudo tar -czf sage-chromadb-backup.tar.gz /opt/sage/chroma_db

# 3. Documents
sudo tar -czf sage-data-backup.tar.gz /opt/sage/data

# 4. Nginx configuration
sudo cp /etc/nginx/sites-available/sage sage-nginx-backup.conf
```

### Automated Backups

Create `/etc/cron.daily/sage-backup`:

```bash
#!/bin/bash
BACKUP_DIR="/backup/sage"
DATE=$(date +%Y%m%d)

mkdir -p $BACKUP_DIR
cd /opt/sage

# Backup vector database
tar -czf $BACKUP_DIR/chromadb-$DATE.tar.gz chroma_db

# Backup configuration
tar -czf $BACKUP_DIR/config-$DATE.tar.gz .env .streamlit

# Keep only last 7 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
```

```bash
sudo chmod +x /etc/cron.daily/sage-backup
```

---

## Scaling

### Vertical Scaling (Single Server)

Increase resources:
- More CPU cores for faster inference
- More RAM for larger models
- Add GPU for 10x faster inference

### Horizontal Scaling (Multiple Servers)

Use load balancer:

```nginx
upstream streamlit_backend {
    least_conn;
    server sage1:8501;
    server sage2:8501;
    server sage3:8501;
}
```

### Shared Storage

Use network storage for ChromaDB:
- NFS mount
- S3-compatible storage
- Shared database

---

## Support

- **GitHub Issues:** https://github.com/EthanHoman/SAGE_/issues
- **Email:** ethan.b.homan@nasa.gov
- **Logs:** Check `/var/log/nginx/` and `journalctl -u sage`
