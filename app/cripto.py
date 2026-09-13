import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
 
ITERACOES_PADRAO = 210_000
TAMANHO_CHAVE = 32   # bytes, AES-256
TAMANHO_SAL = 16     # bytes
TAMANHO_NONCE = 12   # bytes, valor recomendado para o GCM

def para_b64(dados: bytes) -> str:
    """Converte bytes em texto Base64, para gravar no banco."""
    return base64.b64encode(dados).decode("ascii")
 
def de_b64(texto: str) -> bytes:
    """Converte texto Base64 de volta para bytes, ao ler do banco."""
    return base64.b64decode(texto)
