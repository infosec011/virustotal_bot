import os
import time
import requests
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)
import nest_asyncio

nest_asyncio.apply()

VT_API_KEY = "fe859b7e3e45b05fd7abd192265c7535b0be6eba74922cfce7a5e0d7daad67c1"
VT_HEADERS = {"x-apikey": VT_API_KEY}
TELEGRAM_TOKEN = "7981826920:AAHl5SZ7zgDXdG653a4o6mUqCosQbsFdAAM"

def upload_file(file_path):
    url = "https://www.virustotal.com/api/v3/files"
    with open(file_path, "rb") as f:
        files = {"file": (os.path.basename(file_path), f)}
        r = requests.post(url, headers=VT_HEADERS, files=files)
    if r.status_code == 200:
        return r.json()["data"]["id"]
    return None

def scan_url(url_to_scan):
    api_url = "https://www.virustotal.com/api/v3/urls"
    r = requests.post(api_url, headers=VT_HEADERS, data={"url": url_to_scan})
    if r.status_code == 200:
        return r.json()["data"]["id"]
    return None

def get_analysis(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    while True:
        r = requests.get(url, headers=VT_HEADERS)
        if r.status_code == 200:
            data = r.json()
            attributes = data.get("data", {}).get("attributes", {})
            status = attributes.get("status")
            if status == "completed":
                return data
            elif status is None:
                return None
            else:
                time.sleep(5)
        else:
            return None

def parse_report(report):
    if "data" not in report or "attributes" not in report["data"]:
        return "❌ Tahlil natijalari topilmadi yoki tayyor emas."

    stats = report["data"]["attributes"].get("stats") or report["data"]["attributes"].get("last_analysis_stats")
    if not stats:
        return "❌ Tahlil natijalari topilmadi yoki tayyor emas."

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    result = (
        f"🛡️ Tahlil natijalari:\n"
        f"Zararli: {malicious}\n"
        f"Shubhali: {suspicious}\n"
        f"Zararsiz: {harmless}\n"
        f"Aniqlanmagan: {undetected}\n"
    )

    if malicious > 0:
        result += "\n⚠️ Diqqat! Zararli element topildi!"
    elif suspicious > 0:
        result += "\n⚠️ Ehtiyot bo‘ling! Shubhali elementlar mavjud."
    else:
        result += "\n✅ Xavfsiz ko‘rindi."

    return result

# --- Fayl uchun handler ---
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    file = await update.message.document.get_file()
    os.makedirs("temp", exist_ok=True)
    file_path = f"temp/{file.file_id}"
    await file.download_to_drive(file_path)
    await update.message.reply_text("Fayl qabul qilindi, tahlil qilinyapti...")

    file_id = upload_file(file_path)
    if not file_id:
        await update.message.reply_text("Faylni VirusTotal ga yuborishda xatolik yuz berdi.")
        os.remove(file_path)
        return

    report = get_analysis(file_id)
    if not report:
        await update.message.reply_text("Tahlilni olishda xatolik yuz berdi.")
        os.remove(file_path)
        return

    result_text = parse_report(report)
    await update.message.reply_text(result_text)
    os.remove(file_path)

# --- URL uchun handler ---
async def handle_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    await update.message.reply_text("URL qabul qilindi, tahlil qilinyapti...")

    url_id = scan_url(url)
    if not url_id:
        await update.message.reply_text("URL VirusTotal ga yuborishda xatolik yuz berdi.")
        return

    report = get_analysis(url_id)
    if not report:
        await update.message.reply_text("URL tahlilini olishda xatolik yuz berdi.")
        return

    result_text = parse_report(report)
    await update.message.reply_text(result_text)

# --- /start komandasi ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("📁 Fayl yuborish", callback_data="file")],
        [InlineKeyboardButton("🔗 URL yuborish", callback_data="url")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text("Salom! Nima yubormoqchisiz?", reply_markup=reply_markup)

# --- Tugma bosilganda ---
async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if query.data == "file":
        await query.message.reply_text("📂 Iltimos, fayl yuboring.")
        # Endi kelayotgan faylni handle_file qabul qiladi
    elif query.data == "url":
        await query.message.reply_text("🔗 Iltimos, URL manzilni yuboring.")
        # Endi kelayotgan matnni handle_url qabul qiladi

# --- Asosiy funksiya ---
async def main():
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url))

    print("Bot ishga tushdi...")
    await app.run_polling()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
