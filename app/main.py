# ==========================================
# 1. POST   /cofres                          -> Cria um novo cofre (gera sal, deriva chave com PBKDF2 e salva no Supabase)
# 2. POST   /cofres/{cofre_id}/abrir         -> Valida a senha-mestra usando o verificador (canário)
# 3. POST   /cofres/{cofre_id}/segredos      -> Cifra um segredo (AES-GCM) e o cadastra no banco
# 4. GET    /cofres/{cofre_id}/segredos      -> Lista apenas os metadados dos segredos (sem expor senhas)
# 5. GET    /cofres/{cofre_id}/segredos/{id} -> Busca e decifra um segredo específico sob demanda
# 6. PUT    /cofres/{cofre_id}/segredos/{id} -> Atualiza um segredo existente (gera novo nonce)
# 7. DELETE /cofres/{cofre_id}/segredos/{id} -> Remove um segredo permanentemente do banco
# ==========================================

from fastapi import FastAPI, Header, HTTPException
from app import banco, cripto
from app.modelos import NovoCofre, NovoSegredo
import uuid

app = FastAPI(title="Cofre de Senhas")

@app.post("/cofres")
def criar_cofre(novo_cofre: NovoCofre):
    # Gera sal e deriva chave
    cofre_id = str(uuid.uuid4())
    sal = cripto.gerar_sal()
    chave = cripto.derivar_chave(novo_cofre.senha_mestra, sal, cripto.ITERACOES_PADRAO)
    
    chave = cripto.derivar_chave(novo_cofre.senha_mestra, sal, cripto.ITERACOES_PADRAO)
    nonce, cripto_b64, etiqueta_b64 = cripto.criar_verificador(chave, str(uuid.uuid4()))
    
    banco.inserir_cofre(
        id_cofre=cofre_id,
        nome=novo_cofre.nome,
        sal=cripto.para_b64(sal),
        iteracoes=cripto.ITERACOES_PADRAO,
        nonce=nonce,
        cripto=cripto_b64,
        etiqueta=etiqueta_b64
    )
    
    return {"mensagem": "Cofre criado com sucesso!"}

@app.get("/cofres/{cofre_id}/segredos")
def listar_segredos(cofre_id: str, x_senha_mestra: str = Header(...)):
    cofre = banco.buscar_cofre(cofre_id)
    if not cofre:
        raise HTTPException(status_code=404, detail="Cofre não encontrado ou sem segredos.")
    
    sal = cripto.de_b64(cofre["kdf_sal"])
    chave = cripto.derivar_chave(x_senha_mestra, sal, cofre["kdf_iteracoes"])
    
    correta = cripto.senha_mestra_correta(
        chave, 
        cofre["verificador_nonce"], 
        cofre["verificador_criptograma"], 
        cofre["verificador_etiqueta"], 
        cofre_id
    )
    
    if not correta:
        raise HTTPException(status_code=401, detail="Senha-mestra incorreta")
    
    # Retorna a listagem segura de metadados
    return banco.listar_segredos(cofre_id)