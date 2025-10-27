# bot_gateway.py
import threading
import requests
from flask import Flask, request, jsonify
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

FLASK_APP_URL = "http://192.168.10.106:5000"   # where your Flask app (API) runs locally
REGISTER_URL = f"{FLASK_APP_URL}/api/auth/register-external"

# Replace with real tokens
TELEGRAM_TOKEN = "8382223651:AAHxFibITMhyAAWAb644Jv7wlqQAfHR4M5w"
WHATSAPP_TOKEN = "YOUR_WHATSAPP_TOKEN"
PHONE_NUMBER_ID = "YOUR_WHATSAPP_PHONE_NUMBER_ID"
WHATSAPP_API_BASE = "https://graph.facebook.com/v17.0"

# -------------------------
# Telegram part (polling)
# -------------------------
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Hi! To register send: register <no_rujukan> <no_id_pelanggan> <username>")

async def handle_telegram(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    chat_id = update.effective_chat.id

    if not text:
        return

    if text.lower().startswith("register "):
        parts = text.split()
        if len(parts) < 4:
            await update.message.reply_text("Usage: register <no_rujukan> <no_id_pelanggan> <username>")
            return
        no_rujukan, no_id_pelanggan, username = parts[1:4]

        payload = {
            "username": username,
            "no_rujukan": no_rujukan,
            "no_id_pelanggan": no_id_pelanggan,
            "platform": "telegram",
            "platform_id": str(chat_id)
        }
        try:
            r = requests.post(REGISTER_URL, json=payload, timeout=10)
            if r.status_code in (200, 201):
                await update.message.reply_text("? Registration successful.")
            else:
                await update.message.reply_text(f"? Failed: {r.json().get('message','HTTP '+str(r.status_code))}")
        except Exception as e:
            await update.message.reply_text("? Error contacting API: " + str(e))

def start_telegram_bot():
    application = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    application.add_handler(CommandHandler("start", start_cmd))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_telegram))
    application.run_polling()

# -------------------------
# WhatsApp part (Flask webhook)
# -------------------------
app = Flask(__name__)

# GET used by Meta to verify webhook
VERIFY_TOKEN = "verify_me_123"  # set this in Meta console

@app.route("/whatsapp/webhook", methods=["GET", "POST"])
def whatsapp_webhook():
    if request.method == "GET":
        # Verification handshake
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")
        if token == VERIFY_TOKEN:
            return challenge, 200
        return "Verification token mismatch", 403

    data = request.get_json(force=True)
    try:
        # Parse incoming message (WhatsApp Cloud structure)
        entry = data.get("entry", [])[0]
        change = entry.get("changes", [])[0]
        value = change.get("value", {})
        messages = value.get("messages")
        if not messages:
            return jsonify({}), 200

        message = messages[0]
        from_number = message.get("from")
        text = message.get("text", {}).get("body", "").strip()

        if text.lower().startswith("register "):
            parts = text.split()
            if len(parts) < 4:
                send_whatsapp_text(from_number, "Usage: register <no_rujukan> <no_id_pelanggan> <username>")
            else:
                no_rujukan, no_id_pelanggan, username = parts[1:4]
                payload = {
                    "username": username,
                    "no_rujukan": no_rujukan,
                    "no_id_pelanggan": no_id_pelanggan,
                    "platform": "whatsapp",
                    "platform_id": from_number
                }
                r = requests.post(REGISTER_URL, json=payload, timeout=10)
                if r.status_code in (200,201):
                    send_whatsapp_text(from_number, "? Registration successful.")
                else:
                    msg = r.json().get("message", f"HTTP {r.status_code}")
                    send_whatsapp_text(from_number, f"? Registration failed: {msg}")

    except Exception as e:
        print("WhatsApp webhook error:", e)
    return jsonify({}), 200

def send_whatsapp_text(to, body):
    url = f"{WHATSAPP_API_BASE}/{PHONE_NUMBER_ID}/messages"
    headers = {"Authorization": f"Bearer {WHATSAPP_TOKEN}", "Content-Type":"application/json"}
    payload = {
        "messaging_product": "whatsapp",
        "to": to,
        "type": "text",
        "text": {"body": body}
    }
    try:
        requests.post(url, headers=headers, json=payload, timeout=10)
    except Exception as e:
        print("Failed to send whatsapp message:", e)

# -------------------------
# Run both
# -------------------------
if __name__ == "__main__":
    # run telegram in background thread
    t = threading.Thread(target=start_telegram_bot, daemon=True)
    t.start()
    # run Flask app for WhatsApp webhook on port 5001 or same as your main app (if same server ensure endpoints don't conflict)
    app.run(host="0.0.0.0", port=5001)
