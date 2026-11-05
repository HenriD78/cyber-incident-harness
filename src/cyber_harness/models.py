"""Contrats métier des outils. Les chemins de sortie ne sont jamais des arguments LLM."""

import ipaddress
import re
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

Text = Annotated[str, Field(min_length=1, max_length=12000)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Reference(StrictModel):
    fichier: Text
    ligne: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


Refs = Annotated[list[Reference], Field(min_length=1)]


class Finding(StrictModel):
    id: str = Field(pattern=r"^C[0-9]+$")
    description: Text
    statut: Literal["observe", "tentative_bloquee", "present_dans_script", "hypothese"]
    preuves: Refs
    horodatage_source: str | None = None
    utc: str | None = None


class Qualification(StrictModel):
    conclusion: Text
    constat_ids: Annotated[list[str], Field(min_length=1)]


class Analysis(StrictModel):
    constats: Annotated[list[Finding], Field(min_length=1)]
    qualifications: dict[str, Qualification]
    lien_alertes: Text
    lien_prouve: bool = False
    preuves_lien: list[Reference] = Field(default_factory=list)
    injections: list[Reference] = Field(default_factory=list)
    limites: list[str] = Field(default_factory=list)


class IOC(StrictModel):
    type: Literal["ip", "domaine", "url", "hash", "chemin", "compte", "fichier", "autre"]
    valeur: Text
    references: Refs
    contexte: Text
    confiance: Literal["haute", "moyenne", "faible"]
    constat_ids: Annotated[list[str], Field(min_length=1)]
    derivation_id: str | None = None

    @model_validator(mode="after")
    def validate_type(self):
        if self.type == "ip":
            ipaddress.ip_address(self.valeur)
        elif self.type == "hash" and not re.fullmatch(
            r"(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})", self.valeur
        ):
            raise ValueError("Hash MD5/SHA1/SHA256 attendu")
        elif self.type == "url":
            parsed = urlsplit(self.valeur)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                raise ValueError("URL HTTP(S) complète requise")
        elif self.type == "domaine" and not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}",
            self.valeur,
        ):
            raise ValueError("Nom de domaine invalide")
        return self


class Mapping(StrictModel):
    id: str = Field(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")
    constat_ids: Annotated[list[str], Field(min_length=1)]
    justification: Text


class ContainmentAction(StrictModel):
    id: str = Field(pattern=r"^A[0-9]+$")
    action: Text
    cible: Text = Field(
        description="Identifiant exact vérifié, sans préfixe descriptif : admin, et non compte admin. "
        "Préciser le système et le périmètre dans action et justification."
    )
    constat_ids: Annotated[list[str], Field(min_length=1)]
    preuves: Refs
    justification: Text
    impact_attendu: Text
    risques: Text


class Proposal(StrictModel):
    synthese: Text
    actions: Annotated[list[ContainmentAction], Field(min_length=1, max_length=20)]


class ProtocolStep(StrictModel):
    action_id: Text
    cible: Text
    responsable: Text
    prerequis: Annotated[list[Text], Field(min_length=1)]
    etapes: Annotated[list[Text], Field(min_length=1)]
    verifications: Annotated[list[Text], Field(min_length=1)]
    criteres_arret: Annotated[list[Text], Field(min_length=1)]
    retour_arriere: Annotated[list[Text], Field(min_length=1)]


class Protocol(StrictModel):
    proposition_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    actions: Annotated[list[ProtocolStep], Field(min_length=1)]


class ReportSummary(StrictModel):
    resume: Text
    constat_ids: Annotated[list[str], Field(min_length=1)]
    limites: list[str] = Field(default_factory=list)
