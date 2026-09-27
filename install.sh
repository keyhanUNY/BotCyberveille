#!/bin/bash
# ================================================================
#  install.sh v3 — Cyber News Bot + LibreTranslate sur LXC Debian
# ================================================================
set -e

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       Cyber News Bot v3 — Installation           ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── 1. Mise à jour système ────────────────────────────────────────
echo "[1/6] Mise à jour du système..."
apt update -qq && apt upgrade -y -qq

# ── 2. Dépendances ────────────────────────────────────────────────
echo "[2/6] Installation de Python3, pip et outils..."
apt install -y -qq python3 python3-pip python3-venv curl

# ── 3. Dossier du bot ─────────────────────────────────────────────
echo "[3/6] Copie des fichiers dans /opt/cyber-news-bot..."
mkdir -p /opt/cyber-news-bot
cp bot.py config.json sources.json requirements.txt /opt/cyber-news-bot/
cd /opt/cyber-news-bot

# ── 4. Venv Python pour le bot ────────────────────────────────────
echo "[4/6] Environnement virtuel Python..."
python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt
deactivate

# ── 5. LibreTranslate ─────────────────────────────────────────────
echo "[5/6] Installation de LibreTranslate..."
python3 -m venv /opt/libretranslate-venv
source /opt/libretranslate-venv/bin/activate
pip install -q libretranslate
deactivate

echo "  ⬇️  Téléchargement du modèle EN→FR..."
/opt/libretranslate-venv/bin/libretranslate --load-only en,fr --update-models || true

cat > /etc/systemd/system/libretranslate.service << 'EOF'
[Unit]
Description=LibreTranslate — Traduction locale EN→FR
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/libretranslate-venv/bin/libretranslate --host 127.0.0.1 --port 5000 --load-only en,fr
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable libretranslate
systemctl start libretranslate
echo "  ✅ LibreTranslate démarré sur http://localhost:5000"

# ── 6. Cron jobs ──────────────────────────────────────────────────
echo "[6/6] Configuration des cron jobs..."

# Bot toutes les 6h (0h, 6h, 12h, 18h)
CRON_BOT="0 */6 * * * cd /opt/cyber-news-bot && /opt/cyber-news-bot/venv/bin/python bot.py >> /opt/cyber-news-bot/bot.log 2>&1"

( crontab -l 2>/dev/null | grep -v "cyber-news-bot" ; echo "$CRON_BOT" ) | crontab -

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  ✅  Installation terminée !                             ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  ÉTAPES SUIVANTES :                                      ║"
echo "║                                                          ║"
echo "║  1. Configure le webhook :                               ║"
echo "║     nano /opt/cyber-news-bot/config.json                 ║"
echo "║                                                          ║"
echo "║  2. Active/désactive des sources à chaud :               ║"
echo "║     nano /opt/cyber-news-bot/sources.json                ║"
echo "║     (changer "enabled": true/false, sans redémarrer)     ║"
echo "║                                                          ║"
echo "║  3. Test manuel :                                        ║"
echo "║     cd /opt/cyber-news-bot                               ║"
echo "║     ./venv/bin/python bot.py                             ║"
echo "║                                                          ║"
echo "║  4. Logs en direct :                                     ║"
echo "║     tail -f /opt/cyber-news-bot/bot.log                  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
