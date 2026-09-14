# ==========================================
# 1. POST   /cofres                          -> Cria um novo cofre (gera sal, deriva chave com PBKDF2 e salva no Supabase)
# 2. POST   /cofres/{cofre_id}/abrir         -> Valida a senha-mestra usando o verificador (canário)
# 3. POST   /cofres/{cofre_id}/segredos      -> Cifra um segredo (AES-GCM) e o cadastra no banco
# 4. GET    /cofres/{cofre_id}/segredos      -> Lista apenas os metadados dos segredos (sem expor senhas)
# 5. GET    /cofres/{cofre_id}/segredos/{id} -> Busca e decifra um segredo específico sob demanda
# 6. PUT    /cofres/{cofre_id}/segredos/{id} -> Atualiza um segredo existente (gera novo nonce)
# 7. DELETE /cofres/{cofre_id}/segredos/{id} -> Remove um segredo permanentemente do banco
# ==========================================
"""Rotas HTTP e integração entre banco e criptografia."""

from uuid import UUID, uuid4

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app import banco, cripto
from app.modelos import (
    AtualizarSegredo, Identificador, Mensagem, MetadadosSegredo,
    NovoCofre, NovoSegredo, SegredoLido,
)

app = FastAPI(title="Cofre de Senhas", version="1.0.0")


@app.exception_handler(RequestValidationError)
async def erro_de_validacao(request: Request, exc: RequestValidationError):
    # O erro padrão pode incluir o corpo recebido, inclusive senhas.
    erros = [
        {"loc": erro["loc"], "type": erro["type"], "msg": "Campo ausente ou inválido"}
        for erro in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": erros})


@app.exception_handler(banco.ErroBanco)
async def erro_de_banco(request: Request, exc: banco.ErroBanco):
    return JSONResponse(status_code=503, content={
        "detail": "Banco de dados indisponível. Verifique a configuração e a conexão."
    })


def autenticar_cofre(cofre_id: str, senha_mestra: str) -> bytes:
    """Deriva e verifica a chave apenas durante a requisição atual."""
    cofre = banco.buscar_cofre(cofre_id)
    if cofre is None:
        raise HTTPException(status_code=404, detail="Cofre não encontrado")
    try:
        sal = cripto.de_b64(cofre["kdf_sal"])
        chave = cripto.derivar_chave(senha_mestra, sal, cofre["kdf_iteracoes"])
    except (ValueError, TypeError, KeyError):
        raise HTTPException(status_code=500, detail="Parâmetros do cofre inválidos") from None
    if not cripto.senha_mestra_correta(
        chave, cofre["verificador_nonce"], cofre["verificador_criptograma"],
        cofre["verificador_etiqueta"], cofre_id,
    ):
        raise HTTPException(status_code=401, detail="Senha-mestra incorreta")
    return chave


def obter_segredo(cofre_id: str, segredo_id: str) -> dict:
    segredo = banco.buscar_segredo(cofre_id, segredo_id)
    if segredo is None:
        raise HTTPException(status_code=404, detail="Segredo não encontrado")
    return segredo


@app.post("/cofres", status_code=201, response_model=Identificador)
def criar_cofre(novo_cofre: NovoCofre):
    cofre_id = str(uuid4())
    sal = cripto.gerar_sal()
    chave = cripto.derivar_chave(novo_cofre.senha_mestra, sal, cripto.ITERACOES_PADRAO)
    nonce, criptograma, etiqueta = cripto.criar_verificador(chave, cofre_id)
    banco.inserir_cofre(
        id_cofre=cofre_id, nome=novo_cofre.nome, sal_b64=cripto.para_b64(sal),
        iteracoes=cripto.ITERACOES_PADRAO, nonce_b64=nonce,
        cripto_b64=criptograma, etiqueta_b64=etiqueta,
    )
    return {"id": cofre_id}


@app.post("/cofres/{cofre_id}/abrir", response_model=Mensagem)
def abrir_cofre(cofre_id: UUID, x_senha_mestra: str = Header(...)):
    autenticar_cofre(str(cofre_id), x_senha_mestra)
    return {"mensagem": "Cofre aberto com sucesso"}


@app.post("/cofres/{cofre_id}/segredos", status_code=201, response_model=Identificador)
def criar_segredo(cofre_id: UUID, novo_segredo: NovoSegredo, x_senha_mestra: str = Header(...)):
    cofre = str(cofre_id)
    chave = autenticar_cofre(cofre, x_senha_mestra)
    segredo = str(uuid4())
    nonce, criptograma, etiqueta = cripto.cifrar(
        chave, novo_segredo.senha, cripto.aad_segredo(cofre, segredo)
    )
    banco.inserir_segredo(
        id_segredo=segredo, id_cofre=cofre, titulo=novo_segredo.titulo,
        usuario=novo_segredo.usuario, url=novo_segredo.url,
        cripto_b64=criptograma, nonce_b64=nonce, etiqueta_b64=etiqueta,
    )
    return {"id": segredo}


@app.get("/cofres/{cofre_id}/segredos", response_model=list[MetadadosSegredo])
def listar_segredos(cofre_id: UUID, x_senha_mestra: str = Header(...)):
    autenticar_cofre(str(cofre_id), x_senha_mestra)
    return banco.listar_segredos(str(cofre_id))


@app.get("/cofres/{cofre_id}/segredos/{segredo_id}", response_model=SegredoLido)
def ler_segredo(cofre_id: UUID, segredo_id: UUID, x_senha_mestra: str = Header(...)):
    cofre, segredo = str(cofre_id), str(segredo_id)
    chave = autenticar_cofre(cofre, x_senha_mestra)
    registro = obter_segredo(cofre, segredo)
    try:
        senha = cripto.decifrar(
            chave, registro["nonce"], registro["criptograma"], registro["etiqueta"],
            cripto.aad_segredo(cofre, segredo),
        )
    except ValueError:
        raise HTTPException(status_code=500, detail="Registro adulterado") from None
    return {**registro, "senha": senha}


@app.put("/cofres/{cofre_id}/segredos/{segredo_id}", response_model=Identificador)
def atualizar_segredo(
    cofre_id: UUID, segredo_id: UUID, atualizacao: AtualizarSegredo,
    x_senha_mestra: str = Header(...),
):
    cofre, segredo = str(cofre_id), str(segredo_id)
    chave = autenticar_cofre(cofre, x_senha_mestra)
    obter_segredo(cofre, segredo)
    # cifrar sempre gera novo nonce, inclusive quando a senha não muda.
    nonce, criptograma, etiqueta = cripto.cifrar(
        chave, atualizacao.senha, cripto.aad_segredo(cofre, segredo)
    )
    metadados = atualizacao.model_dump(exclude_unset=True, exclude={"senha"})
    alterado = banco.atualizar_segredo(cofre, segredo, nonce, criptograma, etiqueta, metadados)
    if not alterado:
        raise HTTPException(status_code=404, detail="Segredo não encontrado")
    return {"id": segredo}


@app.delete("/cofres/{cofre_id}/segredos/{segredo_id}", response_model=Mensagem)
def remover_segredo(cofre_id: UUID, segredo_id: UUID, x_senha_mestra: str = Header(...)):
    cofre, segredo = str(cofre_id), str(segredo_id)
    autenticar_cofre(cofre, x_senha_mestra)
    obter_segredo(cofre, segredo)
    if not banco.remover_segredo(cofre, segredo):
        raise HTTPException(status_code=404, detail="Segredo não encontrado")
    return {"mensagem": "Segredo removido com sucesso"}
