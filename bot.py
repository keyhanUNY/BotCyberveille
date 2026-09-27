#!/usr/bin/env python3
"""
Cyber News Bot v3
─────────────────
Nouveautés :
  - Score de criticité (CRITICAL / HIGH / MEDIUM / INFO) avec couleurs d'embed
  - @everyone automatique pour les articles CRITICAL
  - Déduplication intelligente : si plusieurs sources parlent du même CVE
    ou sujet, un seul message groupé est envoyé
  - Résumé quotidien à 8h (top N articles de la nuit)
  - Sources rechargées à chaud depuis sources.json (pas besoin de redémarrer)
  - Retry automatique sur rate limit Discord (429)
  - Traduction EN→FR via LibreTranslate
"""

import json
import os
import re
import time
import logging
import hashlib
import feedparser
import requests
from datetime import datetime, timezone

# ─── Logging ──────────────────────────────────────────────────────────────────
# Chemin absolu du dossier où se trouve bot.py — fonctionne quel que soit
# le répertoire courant au moment du lancement (cron, manuel, etc.)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "bot.log")

_fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

_file_handler   = logging.FileHandler(LOG_FILE, encoding="utf-8")
_stream_handler = logging.StreamHandler()
_file_handler.setFormatter(_fmt)
_stream_handler.setFormatter(_fmt)

# On configure le root logger une seule fois avec nos deux handlers
logging.root.setLevel(logging.INFO)
logging.root.handlers = [_file_handler, _stream_handler]

log = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
#  CHARGEMENT CONFIG & SOURCES (rechargement à chaud)
# ══════════════════════════════════════════════════════════════════════════════

def load_config(path=None):
    if path is None:
        path = os.path.join(BASE_DIR, "config.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_sources(path=None):
    if path is None:
        path = os.path.join(BASE_DIR, "sources.json")
    """
    Chargement des sources depuis un fichier séparé.
    Modifie sources.json pendant que le bot tourne → pris en compte au prochain run.
    Seules les sources avec "enabled": true sont utilisées.
    """
    with open(path, "r", encoding="utf-8") as f:
        sources = json.load(f)
    active = [s for s in sources if s.get("enabled", True)]
    log.info(f"📋 {len(active)}/{len(sources)} sources actives chargées depuis {path}")
    return active


# ══════════════════════════════════════════════════════════════════════════════
#  ANTI-DOUBLONS ROBUSTE
# ══════════════════════════════════════════════════════════════════════════════

def make_uid(url, title):
    raw = (url + title).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


SEEN_EXPIRY_DAYS = 60  # Durée de rétention des hash dans seen.json


def load_seen(path):
    """
    Charge le seen.json et retourne (seen_dict, seen_set).
    - seen_dict : { uid: date_iso } pour la sauvegarde
    - seen_set  : set des uid valides utilisé pour les vérifications rapides
    Les entrées de plus de SEEN_EXPIRY_DAYS jours sont purgées au chargement.
    Compatibilité ascendante : migre automatiquement l'ancien format (liste).
    """
    if not os.path.exists(path):
        return {}, set()

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    now = datetime.now()

    # Migration ancien format (liste de strings) → nouveau format (dict)
    if isinstance(raw, list):
        log.info("🔄 Migration seen.json vers le nouveau format (hash + date)...")
        yesterday = now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        seen_dict = {uid: yesterday for uid in raw}
    else:
        seen_dict = raw

    # Nettoyage des entrées expirées (> 60 jours)
    cutoff = now.timestamp() - (SEEN_EXPIRY_DAYS * 86400)
    before = len(seen_dict)
    seen_dict = {
        uid: date_iso
        for uid, date_iso in seen_dict.items()
        if datetime.fromisoformat(date_iso).timestamp() >= cutoff
    }
    purged = before - len(seen_dict)
    if purged > 0:
        log.info(f"🧹 seen.json : {purged} entrée(s) de plus de {SEEN_EXPIRY_DAYS}j supprimée(s).")

    return seen_dict, set(seen_dict.keys())


def save_seen(path, seen_dict):
    """Sauvegarde le dict { uid: date_iso } dans seen.json."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(seen_dict, f, ensure_ascii=False, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
#  DÉDUPLICATION INTELLIGENTE PAR SUJET
# ══════════════════════════════════════════════════════════════════════════════

def load_dedup(path):
    """
    dedup.json stocke les "sujets" déjà traités dans ce run.
    Format : { "sujet_key": { "sources": [...], "title": "...", "url": "..." } }
    Réinitialisé à chaque run pour ne dédupliquer que dans le même run.
    """
    return {}  # Réinitialisation à chaque run, intentionnel


def extract_cve_ids(text):
    """Extrait tous les CVE-XXXX-XXXXX trouvés dans un texte."""
    return set(re.findall(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE))


def make_topic_key(title, summary):
    """
    Crée une clé de sujet pour détecter les doublons cross-sources.
    - Si des CVE sont présents → clé basée sur les CVE
    - Sinon → on extrait les mots significatifs du titre (>4 lettres)
    """
    text = title + " " + summary
    cves = extract_cve_ids(text)
    if cves:
        return "cve:" + ",".join(sorted(cves))

    # Pas de CVE : on garde les mots significatifs du titre
    words = re.findall(r"\b[a-zA-Zéèêëàâîïôùûüç]{5,}\b", title.lower())
    # On ignore les mots trop génériques
    stop = {"windows", "linux", "security", "update", "patch", "flaw",
            "exploit", "vulner", "attack", "report", "multip", "produit"}
    keywords = [w for w in words if w not in stop][:4]
    if keywords:
        return "topic:" + "_".join(sorted(keywords))

    return None  # Pas de clé → pas de dédup


def check_dedup(dedup_store, topic_key, source_name, entry):
    """
    Vérifie si ce sujet a déjà été traité dans ce run.
    Retourne (is_duplicate, existing_entry_or_None)
    """
    if topic_key is None:
        return False, None

    if topic_key in dedup_store:
        existing = dedup_store[topic_key]
        existing["sources"].append(source_name)
        log.info(f"  🔀 Doublon détecté ({topic_key[:40]}) — fusionné avec {existing['primary_source']}")
        return True, existing

    dedup_store[topic_key] = {
        "primary_source": source_name,
        "sources": [source_name],
        "title": entry.get("title", ""),
        "url": entry.get("link", ""),
        "entry": entry
    }
    return False, None


# ══════════════════════════════════════════════════════════════════════════════
#  SCORE DE CRITICITÉ
# ══════════════════════════════════════════════════════════════════════════════

def get_criticality(title, summary, crit_config):
    """
    Détermine le niveau de criticité : CRITICAL, HIGH, MEDIUM, INFO.
    Regarde d'abord les mots-clés CRITICAL, puis HIGH, sinon MEDIUM si CVE présent.
    """
    text = (title + " " + summary).lower()
    cves = extract_cve_ids(title + " " + summary)

    for kw in crit_config["critical_keywords"]:
        if kw.lower() in text:
            return "CRITICAL"

    for kw in crit_config["high_keywords"]:
        if kw.lower() in text:
            return "HIGH"

    if cves:
        return "MEDIUM"

    return "INFO"


def get_criticality_label(level):
    labels = {
        "CRITICAL": "🔴 CRITIQUE",
        "HIGH":     "🟠 ÉLEVÉ",
        "MEDIUM":   "🟡 MODÉRÉ",
        "INFO":     "🔵 INFO"
    }
    return labels.get(level, "🔵 INFO")


# ══════════════════════════════════════════════════════════════════════════════
#  TRADUCTION LIBRETRANSLATE
# ══════════════════════════════════════════════════════════════════════════════

FRENCH_MARKERS = [
    "vulnérabilité", "faille", "mise à jour", "multiples", "noyau",
    "dans les", "produits", "attaquant", "correctif", "avis de sécurité"
]

def is_french(text):
    return any(m in text.lower() for m in FRENCH_MARKERS)


def translate_title(title, lt_url, api_key=""):
    if is_french(title):
        return title
    try:
        payload = {"q": title, "source": "en", "target": "fr", "format": "text"}
        if api_key:
            payload["api_key"] = api_key
        resp = requests.post(f"{lt_url}/translate", json=payload, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("translatedText", title)
    except Exception as e:
        log.debug(f"Traduction échouée : {e}")
    return title


# ══════════════════════════════════════════════════════════════════════════════
#  FILTRAGE MOTS-CLÉS
# ══════════════════════════════════════════════════════════════════════════════

def article_matches(title, summary, keywords):
    text = (title + " " + summary).lower()
    for kw in keywords:
        if kw.lower() in text:
            return kw
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  NETTOYAGE HTML
# ══════════════════════════════════════════════════════════════════════════════

def clean_html(text):
    text = re.sub(r"<[^>]+>", "", text)
    for entity, char in [("&amp;","&"),("&lt;","<"),("&gt;",">"),("&nbsp;"," "),("&#39;","'"),("&quot;",'"')]:
        text = text.replace(entity, char)
    return re.sub(r"\s+", " ", text).strip()


# ══════════════════════════════════════════════════════════════════════════════
#  FLUX RSS
# ══════════════════════════════════════════════════════════════════════════════

def fetch_feed(source):
    log.info(f"Récupération : {source['name']}")
    try:
        feed = feedparser.parse(source["url"])
        log.info(f"  ✅ {len(feed.entries)} articles trouvés.")
        return feed.entries
    except Exception as e:
        log.error(f"  ❌ {source['name']} : {e}")
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  ENVOI DISCORD AVEC RETRY
# ══════════════════════════════════════════════════════════════════════════════

def send_to_discord(webhook_url, payload, max_retries=5):
    for attempt in range(max_retries):
        try:
            resp = requests.post(webhook_url, json=payload, timeout=10)
            if resp.status_code == 204:
                return True
            elif resp.status_code == 429:
                wait = float(resp.json().get("retry_after", 1.0)) + 0.2
                log.debug(f"  ⏳ Rate limit — attente {wait:.1f}s (tentative {attempt+1})")
                time.sleep(wait)
            else:
                log.warning(f"  ⚠️  Discord {resp.status_code} : {resp.text[:120]}")
                return False
        except Exception as e:
            log.error(f"  ❌ Erreur réseau : {e}")
            time.sleep(2)
    log.error("  ❌ Abandon après trop de tentatives.")
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  CONSTRUCTION EMBED ARTICLE
# ══════════════════════════════════════════════════════════════════════════════

def build_article_embed(source, entry, title_fr, original_title,
                        matched_kw, level, crit_config, extra_sources=None):
    """
    Construit le payload Discord pour un article.
    extra_sources : liste de sources supplémentaires si doublon groupé.
    """
    link    = entry.get("link", "")
    color   = crit_config["colors"][level]
    mention = "@everyone\n" if level in crit_config["everyone_on"] else ""

    # Résumé
    raw     = entry.get("summary", entry.get("description", ""))
    summary = clean_html(raw)
    if len(summary) > 350:
        summary = summary[:347] + "…"

    # Date
    published_str = "—"
    t = entry.get("published_parsed")
    if t:
        try:
            published_str = datetime(*t[:6]).strftime("%d/%m/%Y à %H:%M")
        except Exception:
            pass

    # Titre VO si traduit
    if title_fr.strip().lower() != original_title.strip().lower():
        vo_line = f"-# 🔤 *{original_title[:90]}{'…' if len(original_title)>90 else ''}*\n\n"
    else:
        vo_line = ""

    description = f"{vo_line}{summary}" if summary else f"{vo_line}*Aucun résumé disponible.*"

    # Sources groupées si doublon
    source_value = source["name"]
    if extra_sources:
        all_src = [source["name"]] + extra_sources
        source_value = " + ".join(all_src)

    # CVE détectés
    cves = extract_cve_ids(original_title + " " + entry.get("summary", ""))
    cve_field = ", ".join(sorted(cves)) if cves else None

    fields = [
        {"name": "📰 Source",      "value": source_value,              "inline": True},
        {"name": "⚠️ Niveau",      "value": get_criticality_label(level), "inline": True},
        {"name": "🔑 Mot-clé",     "value": f"`{matched_kw}`",         "inline": True},
        {"name": "📅 Publié le",   "value": published_str,             "inline": True},
    ]
    if cve_field:
        fields.append({"name": "🆔 CVE", "value": cve_field, "inline": True})

    embed = {
        "title":       f"{source['emoji']}  {title_fr}",
        "url":         link,
        "description": description,
        "color":       color,
        "fields":      fields,
        "footer":      {"text": "Cyber News Bot"},
        "timestamp":   datetime.now(timezone.utc).isoformat()
    }

    payload = {"content": mention, "embeds": [embed]}
    return payload


# ══════════════════════════════════════════════════════════════════════════════
#  RÉSUMÉ QUOTIDIEN
# ══════════════════════════════════════════════════════════════════════════════

def should_send_daily_summary(config):
    """Vérifie si on est dans la tranche horaire du résumé quotidien."""
    summary_cfg = config.get("daily_summary", {})
    if not summary_cfg.get("enabled", False):
        return False
    target_hour = summary_cfg.get("hour", 8)
    now = datetime.now()
    return now.hour == target_hour


def load_daily_buffer(path="daily_buffer.json"):
    """Charge les articles collectés pour le résumé du jour."""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_daily_buffer(path, articles):
    """Sauvegarde les articles pour le résumé quotidien."""
    # On garde les 50 derniers max
    with open(path, "w", encoding="utf-8") as f:
        json.dump(articles[-50:], f, ensure_ascii=False, indent=2)


def add_to_daily_buffer(buffer, title_fr, url, level, source_name):
    buffer.append({
        "title": title_fr,
        "url":   url,
        "level": level,
        "source": source_name,
        "ts":    datetime.now().isoformat()
    })


def send_daily_summary(webhook_url, webhook_recap_url, buffer, top_n=5):
    """
    Envoie le résumé quotidien sur le canal dédié (webhook_recap_url).
    Fallback sur webhook_url si pas de canal récap configuré.
    """
    target = webhook_recap_url if webhook_recap_url else webhook_url
    if not buffer:
        log.info("📋 Résumé quotidien : aucun article à résumer.")
        return

    # Tri par criticité puis par ordre d'arrivée
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "INFO": 3}
    sorted_buf = sorted(buffer, key=lambda x: order.get(x["level"], 99))
    top = sorted_buf[:top_n]

    lines = []
    for i, art in enumerate(top, 1):
        label = get_criticality_label(art["level"])
        lines.append(f"**{i}.** [{art['title'][:70]}]({art['url']})\n{label} — *{art['source']}*")

    description = "\n\n".join(lines)

    embed = {
        "title":       "📰  Résumé Cyber du jour",
        "description": description,
        "color":       5793266,
        "footer":      {"text": f"Cyber News Bot — Top {top_n} des dernières heures"},
        "timestamp":   datetime.now(timezone.utc).isoformat()
    }

    if send_to_discord(target, {"embeds": [embed]}):
        log.info(f"📋 Résumé quotidien envoyé ({len(top)} articles) sur le canal dédié.")
        # Vide le buffer après envoi réussi — peu importe si appelé depuis main() ou manuellement
        buffer_path = os.path.join(BASE_DIR, "daily_buffer.json")
        save_daily_buffer(buffer_path, [])
        log.info("🗑️  daily_buffer.json vidé.")
    else:
        log.error("❌ Échec envoi du résumé — buffer conservé pour la prochaine tentative.")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    log.info("=" * 60)
    log.info("🚀  Cyber News Bot v3 démarré")
    log.info("=" * 60)

    config      = load_config()
    sources     = load_sources(config.get("sources_file", "sources.json"))
    seen_dict, seen = load_seen(os.path.join(BASE_DIR, config["seen_file"]))
    dedup_store = load_dedup(config.get("dedup_file", "dedup.json"))
    keywords    = config["keywords"]
    webhook     = config["webhook_url"]
    crit_cfg    = config["criticality"]
    lt_url      = config.get("libretranslate_url", "http://localhost:5000")
    lt_key      = config.get("libretranslate_api_key", "")
    daily_buf   = load_daily_buffer(os.path.join(BASE_DIR, "daily_buffer.json"))

    total_posted  = 0
    total_skipped = 0
    total_deduped = 0

    # ── Phase 1 : collecte de tous les articles éligibles ────────
    # On parcourt toutes les sources et on stocke les articles
    # à envoyer dans une liste, sans encore rien poster sur Discord.
    to_send = []

    for source in sources:
        entries = fetch_feed(source)

        for entry in entries:
            url     = entry.get("link", "")
            title   = entry.get("title", "")
            summary = entry.get("summary", entry.get("description", ""))

            # Anti-doublons (articles déjà postés lors des runs précédents)
            uid = make_uid(url, title)
            if uid in seen:
                total_skipped += 1
                continue

            # Filtrage mots-clés
            matched = article_matches(title, summary, keywords)
            if not matched:
                seen.add(uid)
                seen_dict[uid] = datetime.now().isoformat()
                continue

            # Déduplication intelligente cross-sources (même run)
            topic_key = make_topic_key(title, summary)
            is_dup, existing = check_dedup(dedup_store, topic_key, source["name"], entry)
            if is_dup:
                seen.add(uid)
                seen_dict[uid] = datetime.now().isoformat()
                total_deduped += 1
                continue

            # Récupération de la date de publication pour le tri
            pub_ts = 0
            t = entry.get("published_parsed")
            if t:
                try:
                    pub_ts = datetime(*t[:6]).timestamp()
                except Exception:
                    pass

            to_send.append({
                "source":    source,
                "entry":     entry,
                "title":     title,
                "summary":   summary,
                "url":       url,
                "uid":       uid,
                "matched":   matched,
                "pub_ts":    pub_ts,
                "existing":  existing,
            })

    # ── Phase 2 : tri du plus ancien au plus récent ──────────────
    # Les articles sans date (pub_ts=0) sont placés en premier.
    to_send.sort(key=lambda x: x["pub_ts"])
    log.info(f"📦 {len(to_send)} article(s) à envoyer, triés du plus ancien au plus récent.")

    # ── Phase 3 : envoi dans l'ordre chronologique ───────────────
    for item in to_send:
        source  = item["source"]
        entry   = item["entry"]
        title   = item["title"]
        matched = item["matched"]
        uid     = item["uid"]

        # Criticité
        level = get_criticality(title, item["summary"], crit_cfg)

        # Traduction
        title_fr = translate_title(title, lt_url, lt_key)

        # Construction et envoi
        extra_src = item["existing"]["sources"][1:] if item["existing"] else None
        payload   = build_article_embed(
            source, entry, title_fr, title,
            matched, level, crit_cfg, extra_src
        )
        if send_to_discord(webhook, payload):
            log.info(f"  📨 [{level}] {title_fr[:60]}…")
            total_posted += 1
            add_to_daily_buffer(daily_buf, title_fr, item["url"], level, source["name"])

        seen.add(uid)
        seen_dict[uid] = datetime.now().isoformat()
        time.sleep(0.5)

    # ── Résumé quotidien ──────────────────────────────────────────
    if should_send_daily_summary(config):
        webhook_recap = config.get("webhook_recap_url", "")
        send_daily_summary(webhook, webhook_recap, daily_buf, config["daily_summary"]["top_n"])
        # Vide le buffer après envoi
        save_daily_buffer(os.path.join(BASE_DIR, "daily_buffer.json"), [])
    else:
        save_daily_buffer(os.path.join(BASE_DIR, "daily_buffer.json"), daily_buf)

    save_seen(os.path.join(BASE_DIR, config["seen_file"]), seen_dict)

    log.info("=" * 60)
    log.info(f"✅  Terminé — {total_posted} posté(s) | {total_skipped} déjà vu(s) | {total_deduped} dédupliqué(s)")
    log.info("=" * 60)


if __name__ == "__main__":
    main()
