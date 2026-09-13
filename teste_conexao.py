import os
from dotenv import load_dotenv
from supabase import create_client

# Carrega as variáveis do arquivo .env
load_dotenv()

url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")

print("--- VERIFICAÇÃO DE CONFIGURAÇÃO ---")
print(f"SUPABASE_URL: {'Configurada (' + url[:10] + '...)' if url else 'NÃO ENCONTRADA'}")
print(f"SUPABASE_KEY: {'Configurada (' + key[:10] + '...)' if key else 'NÃO ENCONTRADA'}")

if not url or not key:
    print("\n[ERRO] As variáveis não foram carregadas corretamente. Verifique o arquivo .env")
    exit()

try:
    # Tenta conectar ao Supabase e fazer uma consulta simples na tabela cofres
    supabase = create_client(url, key)
    resposta = supabase.table("cofres").select("*").execute()
    print("\n[SUCESSO] Conexão com o Supabase estabelecida com sucesso!")
    print(f"Tabela 'cofres' acessada. Registros encontrados: {len(resposta.data)}")
except Exception as e:
    print(f"\n[ERRO] Falha ao conectar ou consultar o banco de dados: {e}")