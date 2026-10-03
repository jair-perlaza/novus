import os
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

class CryptoVault:
    def __init__(self):
        self.archivo_ecc_priv = "ecc_private.key"
        self.archivo_ecc_pub = "ecc_public.key"
        self.llave_aes = None
        self._inicializar_identidad_ecc()
        self._generar_llave_maestra_aes()

    def _inicializar_identidad_ecc(self):
        """Implementa ECCS (Curve25519) para identidad del servidor"""
        if not os.path.exists(self.archivo_ecc_priv):
            priv_key = x25519.X25519PrivateKey.generate()
            pub_key = priv_key.public_key()
            
            # Guardar Privada
            with open(self.archivo_ecc_priv, "wb") as f:
                f.write(priv_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            # Guardar Pública
            with open(self.archivo_ecc_pub, "wb") as f:
                f.write(pub_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

    def _generar_llave_maestra_aes(self):
        """AES-256 para datos en proceso"""
        self.key_path = "master_aes.key"
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                self.llave_aes = f.read()
        else:
            self.llave_aes = AESGCM.generate_key(bit_length=256)
            with open(self.key_path, "wb") as f:
                f.write(self.llave_aes)
        self.aesgcm = AESGCM(self.llave_aes)

    def proteger(self, texto: str) -> str:
        """Cifrado AES-256-GCM (Autenticado)"""
        try:
            nonce = os.urandom(12)  # Vector de inicialización único
            texto_bytes = texto.encode()
            # AESGCM combina cifrado y verificación de integridad
            token_cifrado = self.aesgcm.encrypt(nonce, texto_bytes, None)
            # Retornamos nonce + dato cifrado en base64
            return base64.b64encode(nonce + token_cifrado).decode('utf-8')
        except Exception:
            return "[ERROR EN CIFRADO]"

    def desproteger(self, token_b64: str) -> str:
        """Descifrado con verificación de integridad"""
        try:
            datos = base64.b64decode(token_b64)
            nonce = datos[:12]
            payload = datos[12:]
            return self.aesgcm.decrypt(nonce, payload, None).decode('utf-8')
        except Exception:
            return "[ERROR: DATO CORRUPTO O LLAVE INVÁLIDA]"

    def get_tls_status(self):
        """Simulación de cumplimiento TLS 1.3"""
        return "TLS_AES_256_GCM_SHA384 (TLS 1.3 Active)"

    def proteger_json(self, payload: dict) -> str:
        """Serializa un diccionario y lo cifra con el mismo esquema de proteger()."""
        return self.proteger(json.dumps(payload, ensure_ascii=True))

    def desproteger_json(self, token_b64: str):
        """Descifra un payload y lo interpreta como JSON."""
        raw = self.desproteger(token_b64)
        if raw.startswith("[ERROR"):
            return {"error": raw}
        try:
            return json.loads(raw)
        except Exception:
            return {"raw": raw}