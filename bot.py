import os
import re
import time
import threading
import unicodedata
import json
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "change-me").strip()
OWNER_CHAT_ID = os.getenv("OWNER_CHAT_ID", "").strip()
BOT_USERNAME = os.getenv("BOT_USERNAME", "").strip().lstrip("@")
JOIN_DELAY_SECONDS = int(os.getenv("JOIN_DELAY_SECONDS", "30"))

API = f"https://api.telegram.org/bot{BOT_TOKEN}"

def tg(method, data=None):
    if not BOT_TOKEN:
        return {"ok": False, "description": "BOT_TOKEN is missing"}
    try:
        r = requests.post(f"{API}/{method}", data=data or {}, timeout=15)
        return r.json()
    except Exception as e:
        print("Telegram API error:", e)
        return {"ok": False, "description": str(e)}

def send_message(chat_id, text, reply_to=None):
    data = {"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"}
    if reply_to:
        data["reply_to_message_id"] = reply_to
    return tg("sendMessage", data)

def delete_message(chat_id, message_id):
    return tg("deleteMessage", {"chat_id": chat_id, "message_id": message_id})

def mute_permanently(chat_id, user_id):
    # No until_date = permanent restriction until an admin/owner manually restores permissions.
    permissions = {
        "can_send_messages": False,
        "can_send_audios": False,
        "can_send_documents": False,
        "can_send_photos": False,
        "can_send_videos": False,
        "can_send_video_notes": False,
        "can_send_voice_notes": False,
        "can_send_polls": False,
        "can_send_other_messages": False,
        "can_add_web_page_previews": False
    }
    return tg("restrictChatMember", {
        "chat_id": chat_id,
        "user_id": user_id,
        "permissions": json.dumps(permissions),
        "use_independent_chat_permissions": "true"
    })

def get_member(chat_id, user_id):
    return tg("getChatMember", {"chat_id": chat_id, "user_id": user_id})

def is_privileged(chat_id, user_id):
    if OWNER_CHAT_ID and str(user_id) == str(OWNER_CHAT_ID):
        return True
    result = get_member(chat_id, user_id)
    if not result.get("ok"):
        return False
    return result.get("result", {}).get("status", "") in ("creator", "administrator")

def report_owner(chat, user, text, reason, action):
    if not OWNER_CHAT_ID:
        print("OWNER_CHAT_ID is not configured; report skipped.")
        return

    name = (user.get("first_name", "") + " " + user.get("last_name", "")).strip() or "Unknown"
    username = "@" + user["username"] if user.get("username") else "no username"
    title = chat.get("title") or chat.get("username") or str(chat.get("id"))

    report = (
        "🚨 MODERATION REPORT\n\n"
        f"Group: {title}\n"
        f"Group ID: {chat.get('id')}\n"
        f"User: {name}\n"
        f"Username: {username}\n"
        f"User ID: {user.get('id')}\n"
        f"Reason: {reason}\n"
        f"Action: {action}\n\n"
        f"Message:\n{text[:3500]}"
    )
    send_message(OWNER_CHAT_ID, report)

ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
URL_RE = re.compile(
    r"(?:https?://|www\.|t\.me/|telegram\.me/|tg://|"
    r"(?:[a-z0-9-]+\.)+(?:com|net|org|in|co|io|me|ly|gg|xyz|site|online|app|dev|info|biz|shop|store|live|pro)(?:[/:?#][^\s]*)?)",
    re.I
)

def normalize_text(text):
    text = ZERO_WIDTH.sub("", text or "")
    text = unicodedata.normalize("NFKC", text).casefold()
    text = re.sub(r"\s+", " ", text).strip()
    return text

def compact_text(text):
    return re.sub(r"[^\w\u0900-\u097f]+", "", normalize_text(text), flags=re.UNICODE)

# Lightweight offline category detector.
# It is intentionally not presented as a complete fixed gaali list.
# It is NOT a neural/LLM model and cannot guarantee 100% semantic detection.
ABUSE_PATTERNS = [
    re.compile(r"\b(?:fuck|f+u+c+k+|motherf+|bastard|asshole|idiot|moron|dumbass|stupid)\b", re.I),
    re.compile(r"\b(?:madarch|behench|bhench|chod|chut|gand|haram|kamina|kamine|kutte|kutti)\w*", re.I),
    re.compile(r"\b(?:bc|mc|bsdk|bkl)\b", re.I),
]
SCAM_PATTERNS = [
    re.compile(r"\b(?:scam|scammer|fraud|fraudster|phishing|ponzi)\b", re.I),
    re.compile(r"\b(?:guaranteed|sure)\s+(?:profit|return|income|double|triple)\b", re.I),
    re.compile(r"\b(?:double|triple)\s+(?:your\s+)?(?:money|cash|amount)\b", re.I),
    re.compile(r"\b(?:send|share|give)\s+(?:me\s+)?(?:otp|cvv|pin|upi|bank|account)\b", re.I),
    re.compile(r"\b(?:otp|cvv|upi|bank\s+details|card\s+details)\b.{0,80}\b(?:send|share|pay|transfer|verify)\b", re.I),
    re.compile(r"\b(?:prize|winner|giveaway|reward)\b.{0,80}\b(?:claim|pay|fee|send|verify)\b", re.I),
]
PROMO_PATTERNS = [
    re.compile(r"\b(?:promo|promotion|referral|refer|affiliate|reseller|advertis|sponsor)\w*\b", re.I),
    re.compile(r"\b(?:my|our)\s+(?:channel|group|bot|app|page|website|service)\b", re.I),
    re.compile(r"\b(?:dm|message|contact|text)\s+me\b", re.I),
    re.compile(r"\b(?:use|enter)\s+(?:my\s+)?(?:code|referral)\b", re.I),
    re.compile(r"\b(?:paid|premium)\s+(?:service|panel|app|membership)\b", re.I),
]

def detect_category(text):
    t = normalize_text(text)
    c = compact_text(text)

    if any(p.search(t) for p in ABUSE_PATTERNS):
        return "abuse"

    # Check compact text for simple obfuscation.
    if re.search(r"(?:fuck|motherf+|asshole|bastard|madarch|behench|bhench|chod|chut|gand|haram|kamina|kamine|kutte|kutti)\w*", c, re.I):
        return "abuse"

    if any(p.search(t) for p in SCAM_PATTERNS):
        return "scam"

    if any(p.search(t) for p in PROMO_PATTERNS):
        return "promotion"

    return None

def contains_link(message):
    text = message.get("text", "") or message.get("caption", "") or ""
    if URL_RE.search(text):
        return True
    entities = (message.get("entities") or []) + (message.get("caption_entities") or [])
    return any(e.get("type") in ("url", "text_link") for e in entities)

def is_channel_forward(message):
    origin = message.get("forward_origin") or {}
    if origin.get("type") == "channel":
        return True
    return message.get("forward_from_chat", {}).get("type") == "channel"

def approve_later(chat_id, user_id):
    time.sleep(JOIN_DELAY_SECONDS)
    result = tg("approveChatJoinRequest", {"chat_id": chat_id, "user_id": user_id})
    print("Join approval:", chat_id, user_id, result)

def queue_join_request(jr):
    chat_id = (jr.get("chat") or {}).get("id")
    user_id = (jr.get("from") or {}).get("id")
    if chat_id is None or user_id is None:
        return
    threading.Thread(target=approve_later, args=(chat_id, user_id), daemon=True).start()

def moderate_message(message):
    chat = message.get("chat") or {}
    user = message.get("from") or {}
        # Private /start command
    if chat.get("type") == "private":
        text = message.get("text", "").strip()

        if text == "/start" or text.startswith("/start "):
            send_message(
                chat["id"],
                "👋 Galvnic Moderation Bot is active.\n\n🛡️ This bot automatically manages join requests and keeps the group clean."
            )
        return
        
    if chat.get("type") not in ("group", "supergroup"):
        return
    if user.get("is_bot"):
        return

    user_id = user.get("id")
    if not user_id or is_privileged(chat.get("id"), user_id):
        return

    if is_channel_forward(message):
        return

    text = message.get("text", "") or message.get("caption", "") or ""
    category = detect_category(text)

    if category == "abuse":
        delete_message(chat["id"], message["message_id"])
        mute = mute_permanently(chat["id"], user_id)
        action = "message deleted + PERMANENTLY muted" if mute.get("ok") else "message deleted; permanent mute failed"
        report_owner(chat, user, text, "Abusive/harassing language detected", action)
        send_message(chat["id"], "🚫 Message removed.\nReason: Abusive language detected.\nUser has been permanently muted.")
        return

    if category == "scam":
        delete_message(chat["id"], message["message_id"])
        mute = mute_permanently(chat["id"], user_id)
        action = "message deleted + PERMANENTLY muted" if mute.get("ok") else "message deleted; permanent mute failed"
        report_owner(chat, user, text, "Suspected scam/fraud content detected", action)
        send_message(chat["id"], "🚫 Message removed.\nReason: Suspected scam/fraud content detected.\nUser has been permanently muted.")
        return

    if category == "promotion":
        send_message(chat["id"], "@GVM_TRUST ONLY TRUSTED CONTACT ONLY OWNER", reply_to=message["message_id"])
        delete_message(chat["id"], message["message_id"])
        mute = mute_permanently(chat["id"], user_id)
        action = "message deleted + PERMANENTLY muted" if mute.get("ok") else "message deleted; permanent mute failed"
        report_owner(chat, user, text, "Promotion/self-advertising detected", action)
        return

    if contains_link(message):
        delete_message(chat["id"], message["message_id"])

def handle_update(update):
    if "chat_join_request" in update:
        queue_join_request(update["chat_join_request"])
        return
    if "channel_post" in update or "edited_channel_post" in update:
        return
    message = update.get("message")
    if message:
        moderate_message(message)

@app.get("/")
def health():
    return jsonify({
        "ok": True,
        "service": "Galvnic Moderation Bot",
        "join_delay_seconds": JOIN_DELAY_SECONDS,
        "mute": "permanent_until_admin_unmutes"
    })

@app.post("/webhook/<path:secret>")
def webhook(secret):
    if secret != WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "forbidden"}), 403
    update = request.get_json(silent=True) or {}
    try:
        handle_update(update)
    except Exception as e:
        print("Update error:", e)
    return jsonify({"ok": True})

@app.get("/register-webhook/<path:secret>")
def register_webhook(secret):
    if secret != WEBHOOK_SECRET:
        return jsonify({"ok": False, "error": "forbidden"}), 403

    base_url = os.getenv("RENDER_EXTERNAL_URL", "").strip().rstrip("/")
    if not base_url:
        return jsonify({"ok": False, "error": "Set RENDER_EXTERNAL_URL first"}), 400

    result = tg("setWebhook", {
        "url": f"{base_url}/webhook/{WEBHOOK_SECRET}",
        "allowed_updates": json.dumps(["message", "chat_join_request"])
    })
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
