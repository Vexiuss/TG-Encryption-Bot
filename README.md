# 🤖 TG Encryption Bot

A secure Telegram bot that provides **AES** and **RSA** encryption/decryption services with an intuitive interface.

## 🔒 Features

- **AES-256 Encryption**: Fast, symmetric encryption for unlimited text length
- **RSA-2048 Encryption**: Asymmetric encryption with key pairs (max 190 characters)
- **Secure Key Generation**: Random keys generated for each encryption
- **Input Validation**: Comprehensive validation and error handling
- **User-Friendly Interface**: Interactive keyboards and step-by-step guidance
- **Detailed Logging**: Complete audit trail for debugging and monitoring

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- A Telegram bot token from [@BotFather](https://t.me/BotFather)

### Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd TG-Encryption-Bot
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   
   Create a `.env` file in the project root:
   ```bash
   API_KEY=your_telegram_bot_api_key_here
   ```
   
   **⚠️ Important**: Never commit your `.env` file to version control!

5. **Run the bot**
   ```bash
   python main.py
   ```

## 🔧 Configuration

### Getting a Bot Token

1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Send `/newbot` and follow the instructions
3. Copy the API token to your `.env` file

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `API_KEY` | Telegram Bot API token | ✅ Yes |

## 📖 Usage Guide

### Basic Commands

- `/start` - Initialize the bot and show main menu
- `/menu` - Return to main menu
- `/help` - Show detailed help information
- `/cancel` - Cancel current operation

### Encryption Process

1. **Start encryption**: Click "🔒 Encrypt"
2. **Choose method**: Select AES or RSA
3. **Enter text**: Type the text you want to encrypt
4. **Save results**: Copy and securely store all encryption components

#### AES Encryption Output
```
🔐 AES Encryption Successful

🔸 Ciphertext: <base64_ciphertext>
🔸 IV (Initialization Vector): <base64_iv>
🔸 Key (Base64): <base64_key>

⚠️ Save all three components to decrypt later!
```

#### RSA Encryption Output
```
🔑 RSA Encryption Successful

🔸 Ciphertext: <base64_ciphertext>
🔸 Private Key (Base64): <base64_private_key>

⚠️ CRITICAL: Save the private key securely!
Without it, you cannot decrypt your message!
```

### Decryption Process

1. **Start decryption**: Click "🔓 Decrypt"
2. **Choose method**: Select AES or RSA (must match encryption method)
3. **Enter components**: Provide all required components step by step

#### For AES Decryption:
- Step 1: Ciphertext
- Step 2: IV (Initialization Vector)
- Step 3: Key

#### For RSA Decryption:
- Step 1: Ciphertext
- Step 2: Private Key

## 🔐 Security Features

### Encryption Standards
- **AES-256-CBC**: Industry-standard symmetric encryption
- **RSA-2048-OAEP**: Secure asymmetric encryption with OAEP padding
- **Random Key Generation**: Cryptographically secure random keys

### Security Measures
- ✅ Input validation and sanitization
- ✅ Base64 format validation
- ✅ Comprehensive error handling
- ✅ No data persistence (nothing stored on servers)
- ✅ Secure logging (sensitive data never logged)
- ✅ API key validation on startup

### Important Security Notes

⚠️ **Critical Security Reminders:**

1. **Never share your encryption keys** with anyone
2. **Store keys securely** - loss means permanent data loss
3. **Use AES for large texts** - RSA has size limitations
4. **This bot is for educational purposes** - review code before production use
5. **The bot doesn't store any data** - all encryption/decryption is stateless

## 🛠️ Development

### Project Structure

```
TG-Encryption-Bot/
├── main.py              # Bot interface and handlers
├── encryption.py        # Encryption/decryption logic
├── requirements.txt     # Python dependencies
├── .env                 # Configuration (not in git)
├── .gitignore          # Git ignore patterns
├── LICENSE             # MIT License
├── README.md           # This file
└── venv/               # Virtual environment
```

### Key Components

- **`main.py`**: Telegram bot interface with conversation handlers
- **`encryption.py`**: Cryptographic operations using pycryptodome
- **Conversation States**: Multi-step user interaction flow
- **Error Handling**: Comprehensive error management and user feedback
- **Logging**: File and console logging for monitoring

### Adding New Features

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests if applicable
5. Update documentation
6. Submit a pull request

## 📝 Logging

The bot generates detailed logs for monitoring and debugging:

- **File**: `bot.log` (created automatically)
- **Console**: Real-time output
- **Levels**: INFO, WARNING, ERROR, CRITICAL

### Log Content
- User interactions (sanitized)
- Encryption/decryption operations
- Error conditions
- Security events

## 🐛 Troubleshooting

### Common Issues

#### Bot doesn't start
- ✅ Check API key in `.env` file
- ✅ Verify internet connection
- ✅ Ensure dependencies are installed

#### Encryption/Decryption fails
- ✅ Verify input format (base64)
- ✅ Check all components are provided
- ✅ Ensure method matches (AES/RSA)

#### Invalid base64 errors
- ✅ Copy components exactly as provided
- ✅ Remove any extra spaces or newlines
- ✅ Ensure complete copy (no truncation)

### Getting Help

1. Check the logs in `bot.log`
2. Verify your input format
3. Test with simple text first
4. Check the [Issues](https://github.com/your-repo/issues) page

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read the development section and submit pull requests for any improvements.

## ⚠️ Disclaimer

This bot is provided for educational and research purposes. While it implements industry-standard encryption algorithms, it should be thoroughly reviewed and tested before any production use. The authors are not responsible for any data loss or security breaches.

