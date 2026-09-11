# Galvnic Moderation Bot — Final

Features:
- Group + channel join requests auto-approved after 30 seconds.
- Group links deleted.
- Abuse, suspected scam/fraud and promotion detected locally.
- Abuse/scam/promotion message is deleted.
- Offending normal member is PERMANENTLY muted.
- Permanent mute has no expiry; an administrator must manually restore the member's permissions.
- Owner receives a private moderation report when OWNER_CHAT_ID is configured.
- Admins, creator and configured owner are exempt from moderation.
- Channel posts are ignored.
- Channel-origin forwards are preserved.
- Promotion warning: @GVM_TRUST ONLY TRUSTED CONTACT ONLY OWNER
- Normal messages are left alone.
- No Firebase.

Important:
The included detector is a lightweight offline classifier, not a neural/LLM AI service. It has internal patterns and normalization for fast moderation. It cannot guarantee detection of every new or obfuscated abusive phrase.

Telegram permissions:
- Channel: Manage Join Requests / invite users.
- Group: Manage Join Requests, Delete Messages, Restrict Members.

Render start command:
gunicorn --workers 1 --threads 4 bot:app

After deployment:
https://YOUR-RENDER-DOMAIN/register-webhook/YOUR_WEBHOOK_SECRET

Old join requests that existed before the bot started receiving webhook updates cannot be guaranteed to be bulk-approved because Telegram Bot API does not provide a general pending-request list.

Permanent unmute:
The bot does not automatically unmute anyone. An admin/owner must manually restore the member's permissions in Telegram.
