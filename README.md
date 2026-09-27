# 🛡️ Cyber News Bot

Agrégateur d'actualités **cybersécurité & IT** qui poste automatiquement dans Discord via webhook.

---

## 📁 Structure des fichiers

```
cyber-news-bot/
├── bot.py            ← Script principal
├── config.json       ← Configuration (sources, mots-clés, webhook)
├── requirements.txt  ← Dépendances Python
├── install.sh        ← Script d'installation automatique
├── seen.json         ← Généré automatiquement (articles déjà postés)
└── bot.log           ← Généré automatiquement (logs)
```

---

## 🚀 Installation sur LXC Proxmox

### 1. Créer le conteneur LXC sur Proxmox

Dans l'interface Proxmox :
- **Template** : Debian 12
- **RAM** : 256 Mo (suffisant)
- **Disque** : 4 Go
- **Réseau** : DHCP ou IP fixe selon ton setup

### 2. Se connecter au LXC et uploader les fichiers

```bash
# Depuis ta machine, copie les fichiers dans le LXC
# Remplace 100 par l'ID de ton conteneur
scp -r cyber-news-bot/ root@<IP_DU_LXC>:/root/
```

### 3. Lancer l'installation

```bash
# Dans le LXC
cd /root/cyber-news-bot
chmod +x install.sh
./install.sh
```

### 4. Configurer le webhook Discord

Édite `/opt/cyber-news-bot/config.json` et remplace :
```
"webhook_url": "REMPLACE_PAR_TON_WEBHOOK_DISCORD"
```

**Comment créer un webhook Discord :**
1. Va dans ton serveur Discord → paramètres du canal
2. Intégrations → Webhooks → Créer un webhook
3. Copie l'URL et colle-la dans config.json

### 5. Tester manuellement

```bash
cd /opt/cyber-news-bot
./venv/bin/python bot.py
```

---

## ⚙️ Configuration

### Ajouter une source RSS

Dans `config.json`, ajoute un objet dans `sources` :
```json
{
  "name": "Nom du site",
  "url": "https://exemple.com/feed/",
  "emoji": "🔒"
}
```

### Modifier les mots-clés

Ajoute ou retire des termes dans la liste `keywords` de `config.json`.
La recherche est insensible à la casse.

### Changer la fréquence

Le cron est configuré toutes les 6h (`0 */6 * * *`).
Pour modifier : `crontab -e`

---

## 📋 Sources configurées par défaut

| Source | Type | Langue |
|--------|------|--------|
| The Hacker News | Cyber international | EN |
| Bleeping Computer | Cyber + Windows | EN |
| CERT-FR | Alertes officielles | FR |
| Microsoft Security | Patches Windows | EN |
| IT Connect | Actu IT générale | FR |

---

## 🐛 Dépannage

**Aucun article posté ?**
- Vérifie que le webhook Discord est correct
- Lance `./venv/bin/python bot.py` et lis les logs
- Supprime `seen.json` pour forcer un re-scan complet

**Trop d'articles ?**
- Réduis la liste `keywords` dans `config.json`

**Logs en temps réel :**
```bash
tail -f /opt/cyber-news-bot/bot.log
```
