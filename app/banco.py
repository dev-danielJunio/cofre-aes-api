import os
from dotenv import load_dotenv
from supabase import create_client, Client
 
load_dotenv()          # lê o arquivo .env
 
supabase: Client = create_client(
    os.environ["SUPABASE_URL"],
    os.environ["SUPABASE_KEY"],
)

# Funções do cofre

def inserir_cofre(id_cofre: str, nome: str, sal_b64: str, iteracoes: int, 
                  nonce_b64: str, cripto_b64: str, etiqueta_b64: str):
    """Insere um novo cofre no banco de dados"""
    supabase.table("cofres").insert({
        "id": id_cofre,
        "nome": nome,
        "kdf_sal": sal_b64,
        "kdf_iteracoes": iteracoes,
        "verificador_nonce": nonce_b64,
        "verificador_criptograma": cripto_b64,
        "verificador_etiqueta": etiqueta_b64
    }).execute()
    
def buscar_cofre(id_cofre: str):
    """Busca um cofre pelo ID"""
    resposta = supabase.table("cofres").select("*").eq("id", id_cofre).execute()
    if resposta.data:
        return resposta.data[0]
    return None

# Funções de segredos

def inserir_segredo(id_segredo: str, id_cofre: str, titulo: str, usuario: str | None, url: str | None, cripto_b64: str, nonce_b64: str, etiqueta_b64: str):
    """Insere um novo segredo no banco de dados"""
    supabase.table("segredos").insert({
        "id": id_segredo,
        "cofre_id": id_cofre,
        "titulo": titulo,
        "usuario": usuario,
        "url": url,
        "criptograma": cripto_b64,
        "nonce": nonce_b64,
        "etiqueta": etiqueta_b64
    }).execute()
    
def buscar_segredos(id_cofre: str):
    """Busca todos os segredos de um cofre pelo ID do cofre"""
    resposta = supabase.table("segredos").select("*").eq("cofre_id", id_cofre).execute()
    return resposta.data

