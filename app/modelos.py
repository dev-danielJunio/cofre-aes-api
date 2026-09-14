"""Contratos de entrada e saída da API."""

from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, Field, field_validator


class NovoCofre(BaseModel):
    nome: str = Field(min_length=1)
    senha_mestra: str = Field(min_length=1, repr=False)


class NovoSegredo(BaseModel):
    titulo: str = Field(min_length=1)
    usuario: str | None = None
    url: str | None = None
    senha: str = Field(min_length=1, repr=False)


class AtualizarSegredo(BaseModel):
    senha: str = Field(min_length=1, repr=False)
    titulo: str | None = Field(default=None, min_length=1)
    usuario: str | None = None
    url: str | None = None

    @field_validator("titulo")
    @classmethod
    def titulo_nao_nulo(cls, valor):
        if valor is None:
            raise ValueError("O título pode ser omitido, mas não pode ser nulo")
        return valor


class Identificador(BaseModel):
    id: UUID


class Mensagem(BaseModel):
    mensagem: str


class MetadadosSegredo(BaseModel):
    id: UUID
    titulo: str
    usuario: str | None = None
    url: str | None = None
    criado_em: datetime


class SegredoLido(MetadadosSegredo):
    senha: str = Field(repr=False)
