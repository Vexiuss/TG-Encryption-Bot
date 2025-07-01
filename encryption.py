from typing import Callable, Dict
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64
import logging
import re

# Set up logging for the encryption module
logger = logging.getLogger(__name__)

class Encryption:
    def __init__(self, key: str = None):
        # If no key is provided, generate a random 32-byte key for AES
        if key is None:
            self.key = get_random_bytes(32)
        else:
            self.key = key.encode('utf-8') if isinstance(key, str) else key
        
        # Fixed: Use encryption methods for encryption and decryption methods for decryption
        self.encrypt_methods: Dict[str, Callable] = {
            "AES": self.aes_encrypt,
            "DES": self.aes_encrypt,  # Using AES as DES is deprecated
            "RSA": self.rsa_encrypt,
        }
        
        self.decrypt_methods: Dict[str, Callable] = {
            "AES": self.aes_decrypt,
            "DES": self.aes_decrypt,
            "RSA": self.rsa_decrypt,
            "RSA_DECRYPT": self.rsa_decrypt,
        }
    
    def _is_valid_base64(self, data: str) -> bool:
        """Validate if a string is valid base64."""
        try:
            # Check if string contains only valid base64 characters
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', data):
                return False
            # Try to decode
            base64.b64decode(data, validate=True)
            return True
        except Exception:
            return False
    
    def encrypt(self, data: str, method: str) -> str:
        """Encrypt data using the specified method."""
        if not data or not isinstance(data, str):
            logger.error(f"Invalid input data for encryption: {type(data)}")
            return "❌ Invalid input: Data must be a non-empty string."
        
        if not method or method not in self.encrypt_methods:
            logger.error(f"Unsupported encryption method: {method}")
            return f"❌ Unsupported encryption method: {method}. Available methods: {', '.join(self.encrypt_methods.keys())}"
        
        encryption_method = self.encrypt_methods.get(method)
        try:
            logger.info(f"Encrypting data using {method} method")
            encrypted_data = encryption_method(data)
            logger.info(f"Successfully encrypted data using {method}")
            return encrypted_data
        except Exception as e:
            logger.error(f"Encryption failed with {method}: {str(e)}", exc_info=True)
            return f"❌ Encryption error with {method}: {str(e)}"

    def decrypt(self, data: str, method: str, key=None) -> str:
        """Decrypt data using the specified method."""
        if not data or not isinstance(data, str):
            logger.error(f"Invalid input data for decryption: {type(data)}")
            return "❌ Invalid input: Data must be a non-empty string."
        
        if not method or method not in self.decrypt_methods:
            logger.error(f"Unsupported decryption method: {method}")
            return f"❌ Unsupported decryption method: {method}. Available methods: {', '.join(self.decrypt_methods.keys())}"
        
        if key is None:
            key = self.key
            
        decryption_method = self.decrypt_methods.get(method)
        try:
            logger.info(f"Decrypting data using {method} method")
            decrypted_data = decryption_method(data=data, key=key)
            logger.info(f"Successfully decrypted data using {method}")
            return decrypted_data
        except Exception as e:
            logger.error(f"Decryption failed with {method}: {str(e)}", exc_info=True)
            return f"❌ Decryption error with {method}: {str(e)}"
    
    def aes_encrypt(self, data: str) -> str:
        """Encrypt data using AES with a random key. Returns iv:ciphertext:key (all base64)."""
        try:
            # AES encryption logic with random key per encryption
            key = get_random_bytes(32)
            cipher = AES.new(key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
            iv = base64.b64encode(cipher.iv).decode('utf-8')
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            key_b64 = base64.b64encode(key).decode('utf-8')
            
            logger.debug(f"AES encryption successful. IV length: {len(iv)}, CT length: {len(ct)}, Key length: {len(key_b64)}")
            return f"{iv}:{ct}:{key_b64}"
        except Exception as e:
            logger.error(f"AES encryption failed: {str(e)}", exc_info=True)
            raise Exception(f"AES encryption failed: {str(e)}")

    def aes_decrypt(self, data: str, key: str = None) -> str:
        """Decrypt AES data. Expects iv:ciphertext:key (all base64) or key as argument."""
        try:
            parts = data.split(":")
            if len(parts) == 3:
                iv_b64, ct_b64, key_b64 = parts
                # Validate base64 format
                if not all(self._is_valid_base64(part) for part in [iv_b64, ct_b64, key_b64]):
                    raise ValueError("Invalid base64 format in encrypted data")
                key = base64.b64decode(key_b64)
            elif len(parts) == 2 and key is not None:
                iv_b64, ct_b64 = parts
                if not all(self._is_valid_base64(part) for part in [iv_b64, ct_b64]):
                    raise ValueError("Invalid base64 format in encrypted data")
                if isinstance(key, str):
                    if not self._is_valid_base64(key):
                        raise ValueError("Invalid base64 format in key")
                    key = base64.b64decode(key)
            else:
                raise ValueError("Invalid AES encrypted data format. Expected 'iv:ciphertext:key' or 'iv:ciphertext' with separate key")
            
            iv = base64.b64decode(iv_b64)
            ct = base64.b64decode(ct_b64)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            
            logger.debug(f"AES decryption successful")
            return pt.decode('utf-8')
        except Exception as e:
            logger.error(f"AES decryption failed: {str(e)}", exc_info=True)
            raise Exception(f"AES decryption failed: {str(e)}")
    
    def rsa_encrypt(self, data: str) -> str:
        """Encrypt data using a new RSA key pair. Returns ciphertext:privatekey (both base64)."""
        try:
            # Validate input length for RSA (RSA has size limits)
            max_length = 190  # Conservative limit for 2048-bit RSA with OAEP padding
            if len(data.encode('utf-8')) > max_length:
                raise ValueError(f"Data too long for RSA encryption. Maximum {max_length} bytes, got {len(data.encode('utf-8'))}")
            
            # Generate a new RSA key pair for each encryption
            key = RSA.generate(2048)
            public_key = key.publickey()
            cipher = PKCS1_OAEP.new(public_key)
            ct_bytes = cipher.encrypt(data.encode('utf-8'))
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            private_key_b64 = base64.b64encode(key.export_key()).decode('utf-8')
            
            logger.debug(f"RSA encryption successful. CT length: {len(ct)}, Private key length: {len(private_key_b64)}")
            return f"{ct}:{private_key_b64}"
        except Exception as e:
            logger.error(f"RSA encryption failed: {str(e)}", exc_info=True)
            raise Exception(f"RSA encryption failed: {str(e)}")

    def rsa_decrypt(self, data: str, key: str = None) -> str:
        """Decrypt RSA data. Expects ciphertext:privatekey (both base64)."""
        try:
            parts = data.split(":")
            if len(parts) != 2:
                raise ValueError("Invalid RSA encrypted data format. Expected 'ciphertext:privatekey'")
            
            ct_b64, private_key_b64 = parts
            
            # Validate base64 format
            if not all(self._is_valid_base64(part) for part in [ct_b64, private_key_b64]):
                raise ValueError("Invalid base64 format in encrypted data")
            
            # Decrypt using provided private key (base64)
            private_key = RSA.import_key(base64.b64decode(private_key_b64))
            cipher = PKCS1_OAEP.new(private_key)
            ct = base64.b64decode(ct_b64)
            pt = cipher.decrypt(ct)
            
            logger.debug(f"RSA decryption successful")
            return pt.decode('utf-8')
        except Exception as e:
            logger.error(f"RSA decryption failed: {str(e)}", exc_info=True)
            raise Exception(f"RSA decryption failed: {str(e)}")

# Example usage (commented out for production)
# en = Encryption("dwakokskdpowa")
# s = en.encrypt("Hello", "RSA")
# print(s)