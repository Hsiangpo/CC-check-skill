#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Country profile definitions for CC-Check target inference."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CountryProfile:
    country_code: str
    locales: tuple[str, ...]
    languages: tuple[str, ...]
    timezone_prefixes: tuple[str, ...]


COUNTRY_PROFILES: dict[str, CountryProfile] = {
    "US": CountryProfile("US", ("en_US.UTF-8",), ("en_US",), ("America/",)),
    "GB": CountryProfile("GB", ("en_GB.UTF-8",), ("en_GB",), ("Europe/London",)),
    "CA": CountryProfile("CA", ("en_CA.UTF-8", "fr_CA.UTF-8"), ("en_CA", "fr_CA"), ("America/",)),
    "AU": CountryProfile("AU", ("en_AU.UTF-8",), ("en_AU",), ("Australia/",)),
    "NZ": CountryProfile("NZ", ("en_NZ.UTF-8",), ("en_NZ",), ("Pacific/Auckland",)),
    "IE": CountryProfile("IE", ("en_IE.UTF-8",), ("en_IE",), ("Europe/Dublin",)),
    "DE": CountryProfile("DE", ("de_DE.UTF-8",), ("de_DE",), ("Europe/Berlin",)),
    "FR": CountryProfile("FR", ("fr_FR.UTF-8",), ("fr_FR",), ("Europe/Paris",)),
    "ES": CountryProfile("ES", ("es_ES.UTF-8",), ("es_ES",), ("Europe/Madrid",)),
    "PT": CountryProfile("PT", ("pt_PT.UTF-8",), ("pt_PT",), ("Europe/Lisbon", "Atlantic/")),
    "IT": CountryProfile("IT", ("it_IT.UTF-8",), ("it_IT",), ("Europe/Rome",)),
    "NL": CountryProfile("NL", ("nl_NL.UTF-8",), ("nl_NL",), ("Europe/Amsterdam",)),
    "BE": CountryProfile("BE", ("nl_BE.UTF-8", "fr_BE.UTF-8"), ("nl_BE", "fr_BE"), ("Europe/Brussels",)),
    "CH": CountryProfile("CH", ("de_CH.UTF-8", "fr_CH.UTF-8", "it_CH.UTF-8"), ("de_CH", "fr_CH", "it_CH"), ("Europe/Zurich",)),
    "AT": CountryProfile("AT", ("de_AT.UTF-8",), ("de_AT",), ("Europe/Vienna",)),
    "SE": CountryProfile("SE", ("sv_SE.UTF-8",), ("sv_SE",), ("Europe/Stockholm",)),
    "NO": CountryProfile("NO", ("nb_NO.UTF-8",), ("nb_NO",), ("Europe/Oslo",)),
    "DK": CountryProfile("DK", ("da_DK.UTF-8",), ("da_DK",), ("Europe/Copenhagen",)),
    "FI": CountryProfile("FI", ("fi_FI.UTF-8",), ("fi_FI",), ("Europe/Helsinki",)),
    "PL": CountryProfile("PL", ("pl_PL.UTF-8",), ("pl_PL",), ("Europe/Warsaw",)),
    "CZ": CountryProfile("CZ", ("cs_CZ.UTF-8",), ("cs_CZ",), ("Europe/Prague",)),
    "HU": CountryProfile("HU", ("hu_HU.UTF-8",), ("hu_HU",), ("Europe/Budapest",)),
    "RO": CountryProfile("RO", ("ro_RO.UTF-8",), ("ro_RO",), ("Europe/Bucharest",)),
    "GR": CountryProfile("GR", ("el_GR.UTF-8",), ("el_GR",), ("Europe/Athens",)),
    "TR": CountryProfile("TR", ("tr_TR.UTF-8",), ("tr_TR",), ("Europe/Istanbul",)),
    "JP": CountryProfile("JP", ("ja_JP.UTF-8",), ("ja_JP",), ("Asia/Tokyo",)),
    "KR": CountryProfile("KR", ("ko_KR.UTF-8",), ("ko_KR",), ("Asia/Seoul",)),
    "SG": CountryProfile("SG", ("en_SG.UTF-8",), ("en_SG",), ("Asia/Singapore",)),
    "HK": CountryProfile("HK", ("en_HK.UTF-8", "zh_HK.UTF-8"), ("en_HK", "zh_HK"), ("Asia/Hong_Kong",)),
    "TW": CountryProfile("TW", ("zh_TW.UTF-8",), ("zh_TW",), ("Asia/Taipei",)),
    "MY": CountryProfile("MY", ("en_MY.UTF-8", "ms_MY.UTF-8"), ("en_MY", "ms_MY"), ("Asia/Kuala_Lumpur",)),
    "TH": CountryProfile("TH", ("th_TH.UTF-8",), ("th_TH",), ("Asia/Bangkok",)),
    "VN": CountryProfile("VN", ("vi_VN.UTF-8",), ("vi_VN",), ("Asia/Ho_Chi_Minh",)),
    "ID": CountryProfile("ID", ("id_ID.UTF-8",), ("id_ID",), ("Asia/Jakarta", "Asia/Makassar", "Asia/Jayapura")),
    "PH": CountryProfile("PH", ("en_PH.UTF-8",), ("en_PH",), ("Asia/Manila",)),
    "IN": CountryProfile("IN", ("en_IN.UTF-8",), ("en_IN",), ("Asia/Kolkata",)),
    "AE": CountryProfile("AE", ("en_AE.UTF-8", "ar_AE.UTF-8"), ("en_AE", "ar_AE"), ("Asia/Dubai",)),
    "SA": CountryProfile("SA", ("ar_SA.UTF-8",), ("ar_SA",), ("Asia/Riyadh",)),
    "IL": CountryProfile("IL", ("he_IL.UTF-8",), ("he_IL",), ("Asia/Jerusalem",)),
    "ZA": CountryProfile("ZA", ("en_ZA.UTF-8",), ("en_ZA",), ("Africa/Johannesburg",)),
    "NG": CountryProfile("NG", ("en_NG.UTF-8",), ("en_NG",), ("Africa/Lagos",)),
    "KE": CountryProfile("KE", ("en_KE.UTF-8", "sw_KE.UTF-8"), ("en_KE", "sw_KE"), ("Africa/Nairobi",)),
    "EG": CountryProfile("EG", ("ar_EG.UTF-8",), ("ar_EG",), ("Africa/Cairo",)),
    "MA": CountryProfile("MA", ("ar_MA.UTF-8", "fr_MA.UTF-8"), ("ar_MA", "fr_MA"), ("Africa/Casablanca",)),
    "BR": CountryProfile("BR", ("pt_BR.UTF-8",), ("pt_BR",), ("America/Sao_Paulo", "America/")),
    "MX": CountryProfile("MX", ("es_MX.UTF-8",), ("es_MX",), ("America/Mexico_City", "America/")),
    "AR": CountryProfile("AR", ("es_AR.UTF-8",), ("es_AR",), ("America/Argentina/",)),
    "CL": CountryProfile("CL", ("es_CL.UTF-8",), ("es_CL",), ("America/Santiago",)),
    "CO": CountryProfile("CO", ("es_CO.UTF-8",), ("es_CO",), ("America/Bogota",)),
    "PE": CountryProfile("PE", ("es_PE.UTF-8",), ("es_PE",), ("America/Lima",)),
}

IANA_TIMEZONE_TO_LOCALE: dict[str, tuple[str | None, str | None]] = {
    code: (profile.locales[0] if profile.locales else None, profile.languages[0] if profile.languages else None)
    for code, profile in COUNTRY_PROFILES.items()
}


def resolve_country_profile(country_code: str | None) -> CountryProfile | None:
    """Return a country profile when one is defined."""
    if not country_code:
        return None
    return COUNTRY_PROFILES.get(country_code.upper())
