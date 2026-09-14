"""Acesso ao Supabase sem lógica HTTP ou criptografia."""

import os
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from httpx import HTTPError
from postgrest.exceptions import APIError
from supabase import Client, create_client

METADADOS = "id,titulo,usuario,url,criado_em"


class ErroBanco(RuntimeError):
    """Falha de configuração, conexão ou consulta sem incluir credenciais."""


@lru_cache(maxsize=1)
def obter_cliente() -> Client:
    # Só o cliente de conexão é reaproveitado; nenhuma senha-mestra ou chave
    # derivada passa por este módulo ou pelo cache.
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    url, chave = os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY")
    if not url or not chave:
        raise ErroBanco("Configure SUPABASE_URL e SUPABASE_KEY no .env")
    try:
        return create_client(url, chave)
    except Exception:
        raise ErroBanco("Configuração do Supabase inválida") from None


def executar(consulta):
    try:
        return consulta.execute().data
    except (APIError, HTTPError):
        raise ErroBanco("Não foi possível acessar o banco") from None


def inserir_cofre(id_cofre: str, nome: str, sal_b64: str, iteracoes: int,
                  nonce_b64: str, cripto_b64: str, etiqueta_b64: str):
    return executar(obter_cliente().table("cofres").insert({
        "id": id_cofre, "nome": nome, "kdf_sal": sal_b64, "kdf_iteracoes": iteracoes,
        "verificador_nonce": nonce_b64, "verificador_criptograma": cripto_b64,
        "verificador_etiqueta": etiqueta_b64,
    }))


def buscar_cofre(id_cofre: str):
    registros = executar(obter_cliente().table("cofres").select("*").eq("id", id_cofre))
    return registros[0] if registros else None


def inserir_segredo(id_segredo: str, id_cofre: str, titulo: str, usuario: str | None,
                    url: str | None, cripto_b64: str, nonce_b64: str, etiqueta_b64: str):
    return executar(obter_cliente().table("segredos").insert({
        "id": id_segredo, "cofre_id": id_cofre, "titulo": titulo,
        "usuario": usuario, "url": url, "criptograma": cripto_b64,
        "nonce": nonce_b64, "etiqueta": etiqueta_b64,
    }))


def listar_segredos(id_cofre: str):
    return executar(obter_cliente().table("segredos").select(METADADOS)
                    .eq("cofre_id", id_cofre).order("criado_em"))


def buscar_segredos(id_cofre: str):
    """Compatibilidade com o nome anterior, agora somente com metadados."""
    return listar_segredos(id_cofre)


def buscar_segredo(id_cofre: str, id_segredo: str):
    registros = executar(obter_cliente().table("segredos").select("*")
                         .eq("cofre_id", id_cofre).eq("id", id_segredo))
    return registros[0] if registros else None


def atualizar_segredo(id_cofre: str, id_segredo: str, nonce_b64: str,
                      cripto_b64: str, etiqueta_b64: str, metadados: dict | None = None):
    dados = {
        "nonce": nonce_b64, "criptograma": cripto_b64, "etiqueta": etiqueta_b64,
        "atualizado_em": datetime.now(timezone.utc).isoformat(),
    }
    # Nunca permitir alteração do id ou do vínculo com o cofre.
    dados.update({k: v for k, v in (metadados or {}).items() if k in {"titulo", "usuario", "url"}})
    return executar(obter_cliente().table("segredos").update(dados)
                    .eq("cofre_id", id_cofre).eq("id", id_segredo))


def remover_segredo(id_cofre: str, id_segredo: str):
    return executar(obter_cliente().table("segredos").delete()
                    .eq("cofre_id", id_cofre).eq("id", id_segredo))
