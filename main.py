#!/usr/bin/env python
# pylint: disable=unused-argument
# This program is dedicated to the public domain under the CC0 license.

"""
Telegram Encryption Bot - Provides AES and RSA encryption/decryption services
For more information, visit: https://github.com/python-telegram-bot/python-telegram-bot/wiki/InlineKeyboard-Example
"""
import logging
import os
import traceback
import sys
from dotenv import load_dotenv

from telegram import ReplyKeyboardMarkup, KeyboardButton, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Application, CallbackQueryHandler, CommandHandler, ContextTypes, MessageHandler
from telegram.ext.filters import BaseFilter, MessageFilter
from telegram.ext import filters
from telegram.ext import ConversationHandler
from encryption import Encryption

# Enhanced logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("bot.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# Set higher logging level for httpx to avoid all GET and POST requests being logged
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("telegram").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Load environment variables from .env file
env_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(env_path)

API_KEY = os.environ.get('API_KEY')

# Validate API key on startup
if not API_KEY:
    logger.critical("API_KEY not found in environment variables. Please check your .env file.")
    sys.exit(1)

if len(API_KEY) < 20:  # Basic validation
    logger.critical("API_KEY appears to be invalid (too short). Please check your .env file.")
    sys.exit(1)

logger.info("Bot starting up with valid API key")

# Conversation states
ENCRYPT_WAIT_MODE = 1
ENCRYPT_WAIT_TEXT = 2
DECRYPT_WAIT_MODE = 3
DECRYPT_WAIT_KEY  = 4
DECRYPT_WAIT_IV   = 5
DECRYPT_WAIT_CT   = 6
DECRYPT_WAIT_TEXT = 7

# --- Keyboard Layouts as Constants ---
MAIN_KEYBOARD = ReplyKeyboardMarkup(
    [[KeyboardButton("🔒 Encrypt"), KeyboardButton("🔓 Decrypt")]], 
    resize_keyboard=True,
    one_time_keyboard=False
)
ENCRYPT_MODE_INLINE = InlineKeyboardMarkup([
    [InlineKeyboardButton("🔐 AES", callback_data="AES"), 
     InlineKeyboardButton("🔑 RSA", callback_data="RSA")]
])
DECRYPT_MODE_INLINE = InlineKeyboardMarkup([
    [InlineKeyboardButton("🔐 AES", callback_data="AES"), 
     InlineKeyboardButton("🔑 RSA", callback_data="RSA")]
])

# --- Utility Functions ---
def sanitize_user_input(text: str) -> str:
    """Sanitize user input for logging purposes."""
    if not text:
        return "None"
    # For security, don't log the full content, just basic info
    return f"<{len(text)} characters>"

def validate_user_input(text: str, max_length: int = 10000) -> tuple[bool, str]:
    """Validate user input."""
    if not text:
        return False, "Input cannot be empty"
    if len(text) > max_length:
        return False, f"Input too long. Maximum {max_length} characters allowed"
    if len(text.strip()) == 0:
        return False, "Input cannot be only whitespace"
    return True, "Valid"

# --- /start Handler ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send main menu keyboard."""
    user = update.effective_user
    logger.info(f"User {user.id} ({user.first_name}) started the bot")
    
    welcome_message = (
        "🤖 **Welcome to the Encryption Bot!**\n\n"
        "🔒 **Features:**\n"
        "• AES encryption (256-bit, secure)\n"
        "• RSA encryption (2048-bit, secure)\n"
        "• Secure key generation\n\n"
        "Please choose an option below:"
    )
    
    await update.message.reply_text(
        welcome_message, 
        reply_markup=MAIN_KEYBOARD,
        parse_mode='Markdown'
    )

# --- /menu Handler ---
async def menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show main menu."""
    user = update.effective_user
    logger.info(f"User {user.id} requested main menu")
    
    await update.message.reply_text(
        "🏠 **Main Menu**\n\nChoose an option:", 
        reply_markup=MAIN_KEYBOARD,
        parse_mode='Markdown'
    )

# --- Encryption Conversation Handlers ---
async def encrypt_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Ask user for encryption mode using inline keyboard."""
    user = update.effective_user
    logger.info(f"User {user.id} started encryption process")
    
    await update.message.reply_text(
        "🔒 **Encryption Mode Selection**\n\n"
        "Choose your encryption method:\n"
        "• **AES**: Fast, symmetric encryption\n"
        "• **RSA**: Slower, asymmetric encryption (max 190 chars)",
        reply_markup=ENCRYPT_MODE_INLINE,
        parse_mode='Markdown'
    )
    return ENCRYPT_WAIT_MODE

async def encrypt_mode(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle encryption mode selection."""
    user = update.effective_user
    mode = update.callback_query.data
    
    if mode not in ["AES", "RSA"]:
        logger.warning(f"User {user.id} selected invalid encryption mode: {mode}")
        await update.callback_query.answer("❌ Invalid selection")
        return ConversationHandler.END
    
    context.user_data['encryption_mode'] = mode
    logger.info(f"User {user.id} selected {mode} encryption")
    
    await update.callback_query.answer()
    
    if mode == "RSA":
        instruction = (
            f"🔑 **{mode} Encryption Selected**\n\n"
            "📝 Now send the text to encrypt:\n"
            "⚠️ **Note:** RSA has a 190 character limit"
        )
    else:
        instruction = (
            f"🔐 **{mode} Encryption Selected**\n\n"
            "📝 Now send the text to encrypt:"
        )
    
    await update.callback_query.edit_message_text(
        instruction,
        parse_mode='Markdown'
    )
    return ENCRYPT_WAIT_TEXT

# Initialize encryption instance
encryption_instance = Encryption()

async def encrypt_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle text encryption."""
    user = update.effective_user
    user_text = update.message.text
    mode = context.user_data.get('encryption_mode', 'Unknown')
    
    logger.info(f"User {user.id} encrypting {sanitize_user_input(user_text)} with {mode}")
    
    # Validate input
    is_valid, error_msg = validate_user_input(user_text, 10000)
    if not is_valid:
        logger.warning(f"User {user.id} provided invalid input: {error_msg}")
        await update.message.reply_text(
            f"❌ **Invalid Input**\n\n{error_msg}",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
        return ConversationHandler.END
    
    # Additional RSA length check
    if mode == "RSA" and len(user_text.encode('utf-8')) > 190:
        logger.warning(f"User {user.id} provided text too long for RSA: {len(user_text.encode('utf-8'))} bytes")
        await update.message.reply_text(
            f"❌ **Text Too Long for RSA**\n\n"
            f"RSA encryption supports maximum 190 bytes.\n"
            f"Your text is {len(user_text.encode('utf-8'))} bytes.\n\n"
            f"Please use AES for longer texts.",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
        return ConversationHandler.END
    
    try:
        encrypted = encryption_instance.encrypt(user_text, mode)
        
        # Check if encryption failed (returns error message)
        if encrypted.startswith("❌"):
            logger.error(f"Encryption failed for user {user.id} with {mode}: {encrypted}")
            await update.message.reply_text(
                f"❌ **Encryption Failed**\n\n{encrypted}",
                reply_markup=MAIN_KEYBOARD,
                parse_mode='Markdown'
            )
            return ConversationHandler.END
        
        if mode == "AES":
            try:
                iv, ct, key_b64 = encrypted.split(":")
                response = (
                    f"🔐 **AES Encryption Successful**\n\n"
                    f"**🔸 Ciphertext:**\n`{ct}`\n\n"
                    f"**🔸 IV (Initialization Vector):**\n`{iv}`\n\n"
                    f"**🔸 Key (Base64):**\n`{key_b64}`\n\n"
                    f"⚠️ **Save all three components to decrypt later!**"
                )
            except ValueError:
                logger.error(f"Invalid AES encryption format for user {user.id}")
                await update.message.reply_text(
                    "❌ **Encryption Error**\n\nInvalid encryption format received.",
                    reply_markup=MAIN_KEYBOARD,
                    parse_mode='Markdown'
                )
                return ConversationHandler.END
                
        elif mode == "RSA":
            try:
                ct, privkey_b64 = encrypted.split(":")
                response = (
                    f"🔑 **RSA Encryption Successful**\n\n"
                    f"**🔸 Ciphertext:**\n`{ct}`\n\n"
                    f"**🔸 Private Key (Base64):**\n`{privkey_b64}`\n\n"
                    f"⚠️ **CRITICAL: Save the private key securely!**\n"
                    f"Without it, you cannot decrypt your message!"
                )
            except ValueError:
                logger.error(f"Invalid RSA encryption format for user {user.id}")
                await update.message.reply_text(
                    "❌ **Encryption Error**\n\nInvalid encryption format received.",
                    reply_markup=MAIN_KEYBOARD,
                    parse_mode='Markdown'
                )
                return ConversationHandler.END
        else:
            response = f"🔒 **Encryption Result:**\n\n`{encrypted}`"
        
        logger.info(f"Successfully encrypted data for user {user.id} using {mode}")
        await update.message.reply_text(
            response,
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
        
    except Exception as e:
        logger.error(f"Unexpected encryption error for user {user.id}: {str(e)}\n{traceback.format_exc()}")
        await update.message.reply_text(
            f"❌ **Unexpected Error**\n\n"
            f"An unexpected error occurred during encryption.\n"
            f"Please try again or contact support.",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
    
    return ConversationHandler.END

# --- Decryption Conversation Handlers ---
async def decrypt_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start decryption process."""
    user = update.effective_user
    logger.info(f"User {user.id} started decryption process")
    
    await update.message.reply_text(
        "🔓 **Decryption Mode Selection**\n\n"
        "Choose the decryption method:\n"
        "• **AES**: Requires CT, IV, and Key\n"
        "• **RSA**: Requires CT and Private Key",
        reply_markup=DECRYPT_MODE_INLINE,
        parse_mode='Markdown'
    )
    return DECRYPT_WAIT_MODE

async def decrypt_mode(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle decryption mode selection."""
    user = update.effective_user
    mode = update.callback_query.data
    
    if mode not in ["AES", "RSA"]:
        logger.warning(f"User {user.id} selected invalid decryption mode: {mode}")
        await update.callback_query.answer("❌ Invalid selection")
        return ConversationHandler.END
    
    context.user_data['decryption_mode'] = mode
    logger.info(f"User {user.id} selected {mode} decryption")
    
    await update.callback_query.answer()
    await update.callback_query.edit_message_text(
        f"🔓 **{mode} Decryption Selected**\n\n"
        f"📝 Now send the **Ciphertext (CT)**:",
        parse_mode='Markdown'
    )
    return DECRYPT_WAIT_CT

async def decrypt_ct(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle ciphertext input."""
    user = update.effective_user
    ct = update.message.text.strip()
    
    # Validate input
    is_valid, error_msg = validate_user_input(ct)
    if not is_valid:
        logger.warning(f"User {user.id} provided invalid CT: {error_msg}")
        await update.message.reply_text(
            f"❌ **Invalid Ciphertext**\n\n{error_msg}",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
        return ConversationHandler.END
    
    context.user_data["CT"] = ct
    logger.info(f"User {user.id} provided CT for decryption")
    
    mode = context.user_data.get('decryption_mode', 'Unknown')
    
    if mode == "AES":
        await update.message.reply_text(
            "🔐 **AES Decryption - Step 2/3**\n\n"
            "📝 Now send the **IV (Initialization Vector)**:",
            parse_mode='Markdown'
        )
        return DECRYPT_WAIT_IV
    elif mode == "RSA":
        await update.message.reply_text(
            "🔑 **RSA Decryption - Step 2/2**\n\n"
            "📝 Now send the **Private Key (Base64)**:",
            parse_mode='Markdown'
        )
        return DECRYPT_WAIT_KEY
    else:
        logger.error(f"Unknown decryption mode for user {user.id}: {mode}")
        await update.message.reply_text(
            "❌ **Error**\n\nUnknown decryption mode.",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
        return ConversationHandler.END

async def decrypt_iv(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle IV input for AES decryption."""
    user = update.effective_user
    iv = update.message.text.strip()
    
    # Validate input
    is_valid, error_msg = validate_user_input(iv)
    if not is_valid:
        logger.warning(f"User {user.id} provided invalid IV: {error_msg}")
        await update.message.reply_text(
            f"❌ **Invalid IV**\n\n{error_msg}",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
        return ConversationHandler.END
    
    context.user_data["IV"] = iv
    logger.info(f"User {user.id} provided IV for AES decryption")
    
    await update.message.reply_text(
        "🔐 **AES Decryption - Step 3/3**\n\n"
        "📝 Now send the **Key (Base64)**:",
        parse_mode='Markdown'
    )
    return DECRYPT_WAIT_KEY

async def decrypt_key(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Handle key input and perform decryption."""
    user = update.effective_user
    key = update.message.text.strip()
    
    # Validate input
    is_valid, error_msg = validate_user_input(key)
    if not is_valid:
        logger.warning(f"User {user.id} provided invalid key: {error_msg}")
        await update.message.reply_text(
            f"❌ **Invalid Key**\n\n{error_msg}",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
        return ConversationHandler.END
    
    context.user_data["encrypted_key"] = key
    
    # Gather all components
    iv = context.user_data.get("IV")
    ct = context.user_data.get("CT")
    mode = context.user_data.get('decryption_mode')
    
    logger.info(f"User {user.id} attempting {mode} decryption")
    
    # Validate we have all required components
    if mode == "AES" and (not iv or not ct or not key):
        missing = []
        if not iv: missing.append("IV")
        if not ct: missing.append("Ciphertext")
        if not key: missing.append("Key")
        
        logger.warning(f"User {user.id} missing components for AES decryption: {missing}")
        await update.message.reply_text(
            f"❌ **Missing Components**\n\n"
            f"Missing: {', '.join(missing)}\n"
            f"Please start the decryption process again.",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
        return ConversationHandler.END
        
    elif mode == "RSA" and (not ct or not key):
        missing = []
        if not ct: missing.append("Ciphertext")
        if not key: missing.append("Private Key")
        
        logger.warning(f"User {user.id} missing components for RSA decryption: {missing}")
        await update.message.reply_text(
            f"❌ **Missing Components**\n\n"
            f"Missing: {', '.join(missing)}\n"
            f"Please start the decryption process again.",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
        return ConversationHandler.END
    
    try:
        # Prepare data for decryption
        if mode == "AES":
            data = f"{iv}:{ct}:{key}"
        elif mode == "RSA":
            data = f"{ct}:{key}"
        else:
            raise ValueError(f"Unknown decryption mode: {mode}")
        
        # Perform decryption
        decrypted = encryption_instance.decrypt(data=data, method=mode, key=key)
        
        # Check if decryption failed (returns error message)
        if decrypted.startswith("❌"):
            logger.error(f"Decryption failed for user {user.id} with {mode}: {decrypted}")
            await update.message.reply_text(
                f"❌ **Decryption Failed**\n\n{decrypted}",
                reply_markup=MAIN_KEYBOARD,
                parse_mode='Markdown'
            )
        else:
            logger.info(f"Successfully decrypted data for user {user.id} using {mode}")
            await update.message.reply_text(
                f"✅ **Decryption Successful**\n\n"
                f"**📝 Decrypted text:**\n`{decrypted}`",
                reply_markup=MAIN_KEYBOARD,
                parse_mode='Markdown'
            )
        
    except Exception as e:
        logger.error(f"Unexpected decryption error for user {user.id}: {str(e)}\n{traceback.format_exc()}")
        await update.message.reply_text(
            f"❌ **Unexpected Error**\n\n"
            f"An unexpected error occurred during decryption.\n"
            f"Please check your input and try again.",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )
    
    return ConversationHandler.END

# --- General Message Handler ---
async def general_message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle general text messages."""
    text = update.message.text
    user = update.effective_user
    
    if text == "🔒 Encrypt":
        await encrypt_handler(update, context)
    elif text == "🔓 Decrypt":
        await decrypt_handler(update, context)
    else:
        logger.info(f"User {user.id} sent unrecognized message: {sanitize_user_input(text)}")
        await update.message.reply_text(
            "❓ **Unknown Command**\n\n"
            "Please use the buttons below or type /help for assistance.",
            reply_markup=MAIN_KEYBOARD,
            parse_mode='Markdown'
        )

# --- /help Handler ---
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show help information."""
    user = update.effective_user
    logger.info(f"User {user.id} requested help")
    
    help_text = (
        "🤖 **Encryption Bot Help**\n\n"
        "**🔹 Commands:**\n"
        "• `/start` - Start the bot\n"
        "• `/menu` - Show main menu\n"
        "• `/help` - Show this help\n"
        "• `/cancel` - Cancel current operation\n\n"
        "**🔹 How to use:**\n"
        "1. Choose 'Encrypt' or 'Decrypt'\n"
        "2. Select AES or RSA method\n"
        "3. Follow the prompts\n\n"
        "**🔹 Encryption Methods:**\n"
        "• **AES**: Fast, symmetric (unlimited text)\n"
        "• **RSA**: Slower, asymmetric (max 190 chars)\n\n"
        "**🔹 Security:**\n"
        "• Keys are generated randomly\n"
        "• No data is stored on servers\n"
        "• Save your keys securely!\n\n"
        "**⚠️ Important:** Always save your encryption keys!"
    )
    
    await update.message.reply_text(
        help_text,
        reply_markup=MAIN_KEYBOARD,
        parse_mode='Markdown'
    )

# --- /cancel Command ---
async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancel current operation."""
    user = update.effective_user
    logger.info(f"User {user.id} cancelled operation")
    
    await update.message.reply_text(
        "❌ **Operation Cancelled**\n\nReturning to main menu.",
        reply_markup=MAIN_KEYBOARD,
        parse_mode='Markdown'
    )
    return ConversationHandler.END

# --- Error Handler ---
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log the error and send a telegram message to notify the developer."""
    logger.error("Exception while handling an update:", exc_info=context.error)
    
    # Only send error message if we have an update with a message
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(
                "❌ **Unexpected Error**\n\n"
                "An unexpected error occurred. Please try again.\n"
                "If the problem persists, contact support.",
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Failed to send error message: {e}")

def main() -> None:
    """Run the bot."""
    logger.info("Initializing Telegram Bot application")
    
    try:
        application = Application.builder().token(API_KEY).build()

        # Conversation handler for encryption
        encrypt_conv_handler = ConversationHandler(
            entry_points=[MessageHandler(filters.TEXT & filters.Regex(r"^🔒 Encrypt$"), encrypt_handler)],
            states={
                ENCRYPT_WAIT_MODE: [CallbackQueryHandler(encrypt_mode)],
                ENCRYPT_WAIT_TEXT: [MessageHandler(filters.TEXT & ~filters.COMMAND, encrypt_text)]
            },
            fallbacks=[CommandHandler("cancel", cancel)]
        )
        
        # Conversation handler for decryption
        decrypt_conv_handler = ConversationHandler(
            entry_points=[MessageHandler(filters.TEXT & filters.Regex(r"^🔓 Decrypt$"), decrypt_handler)],
            states={
                DECRYPT_WAIT_MODE: [CallbackQueryHandler(decrypt_mode)],
                DECRYPT_WAIT_CT: [MessageHandler(filters.TEXT & ~filters.COMMAND, decrypt_ct)],
                DECRYPT_WAIT_IV: [MessageHandler(filters.TEXT & ~filters.COMMAND, decrypt_iv)],
                DECRYPT_WAIT_KEY: [MessageHandler(filters.TEXT & ~filters.COMMAND, decrypt_key)]
            },
            fallbacks=[CommandHandler("cancel", cancel)]
        )

        # Add handlers
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("menu", menu))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CommandHandler("cancel", cancel))
        application.add_handler(encrypt_conv_handler)
        application.add_handler(decrypt_conv_handler)
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, general_message_handler))
        
        # Add error handler
        application.add_error_handler(error_handler)

        logger.info("Bot handlers configured successfully")
        logger.info("Starting bot polling...")
        
        # Run the bot until the user presses Ctrl-C
        application.run_polling(
            allowed_updates=Update.ALL_TYPES,
            drop_pending_updates=True
        )
        
    except Exception as e:
        logger.critical(f"Failed to start bot: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

