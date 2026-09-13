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


def derivar_chave(senha_mestra: str, sal: bytes,
                  iteracoes: int) -> bytes:
    """Transforma a senhasal, iteracoes-mestra em uma chave de 32 bytes."""
    return PBKDF2(senha_mestra.encode("utf-8"), sal, TAMANHO_CHAVE, iteracoes, hmac_hash_module=SHA256)

def gerar_sal() -> bytes:
    """Sorteia um sal novo para um cofre."""
    return get_random_bytes(TAMANHO_SAL)

def cifrar(chave: bytes, texto_claro: str,
           aad: bytes) -> tuple[str, str, str]:
    nonce = get_random_bytes(TAMANHO_NONCE)
    cifra = AES.new(chave, AES.MODE_GCM, nonce = nonce)
    cifra.update(aad)
    mensagem = texto_claro.encode("utf-8")
    criptograma, etiqueta = cifra.encrypt_and_digest(mensagem)
    return para_b64(nonce), para_b64(criptograma), para_b64(etiqueta)
    """Cifra e devolve (nonce, criptograma, etiqueta) em Base64."""

def decifrar(chave: bytes, nonce_b64: str, cripto_b64: str,
             etiqueta_b64: str, aad: bytes) -> str:
    nonce = de_b64(nonce_b64)
    criptograma = de_b64(cripto_b64)
    etiqueta = de_b64(etiqueta_b64)

    cifra = AES.new(chave, AES.MODE_GCM, nonce=nonce)
    cifra.update(aad)

    resultado = cifra.decrypt_and_verify(criptograma, etiqueta)

    return resultado.decode("utf-8")

    """Decifra e verifica a etiqueta. Lança ValueError na falha.""" 

FRASE_VERIFICADORA = "cofre-ok"
 
def criar_verificador(chave: bytes,
                      cofre_id: str) -> tuple[str, str, str]:
    """Cifra a frase fixa, gravada no registro do cofre."""
    # TODO: chame cifrar() com aad = cofre_id.encode()
 
def senha_mestra_correta(chave, nonce, cripto,
                         etiqueta, cofre_id) -> bool:
    """Tenta decifrar o verificador. Devolve True ou False."""
    # TODO: chame decifrar() dentro de try/except ValueError
    #       True se o texto obtido for igual a FRASE_VERIFICADORA
    #       retorne False se ocorrer ValueError
