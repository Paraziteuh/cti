#!/usr/bin/env python3
"""
Malware IOC Analyzer

Fonctionnalités :
- Hashs (MD5, SHA1, SHA256)
- Extraction de strings ASCII
- IOC : IP, URL, email, clés registre, strings suspectes
- Imports DLL / fonctions (si PE valide via pefile)
- Enrichissement VirusTotal sur le hash SHA256 (--vt)
- Enrichissement "OTX" sur le hash SHA256 (--otx) [actuellement même endpoint que VT]
"""

import argparse
import hashlib
import json
import os
import sys

import pefile
import requests

from ioc import *
from settings import *


#  HASH DU FICHIER
def compute_hashes(path):
    "Calcule MD5, SHA1, SHA256 d'un fichier en streaming."
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


#  EXTRACTION DES STRINGS
def extract_ascii_strings(path, min_length=4):
    """Extrait des chaînes ASCII imprimables depuis un fichier."""
    result = []
    current = []
    with open(path, "rb") as f:
        data = f.read()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                result.append("".join(current))
            current = []
    if len(current) >= min_length:
        result.append("".join(current))
    return result


def extract_iocs(strings):
    """Analyse les strings pour extraire des IOC."""
    ips = set()
    urls = set()
    emails = set()
    regkeys = set()
    suspicious = set()
    for s in strings:
        for m in IP_REGEX.findall(s):
            ips.add(m)
        for m in URL_REGEX.findall(s):
            urls.add(m)
        for m in EMAIL_REGEX.findall(s):
            emails.add(m)
        for m in REGKEY_REGEX.findall(s):
            regkeys.add(m)
        for kw in SUSPICIOUS_KEYWORDS:
            if kw.lower() in s.lower():
                suspicious.add(s)
    return {
        "ips": sorted(list(ips)),
        "urls": sorted(list(urls)),
        "emails": sorted(list(emails)),
        "registry_keys": sorted(list(regkeys)),
        "suspicious_strings": sorted(list(suspicious)),
    }


#  ANALYSE PE
def analyze_pe(path):
    """Analyse un fichier PE et extrait les imports DLL + fonctions."""
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError:
        return None  # pas un PE
    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode(errors="ignore")
            funcs = [
                imp.name.decode(errors="ignore") if imp.name else None
                for imp in entry.imports
            ]
            imports.append({
                "dll": dll_name,
                "functions": funcs
            })
    return {
        "imports": imports
    }


#  ENRICHISSEMENT VIRUSTOTAL
def enrich_with_virustotal(sha256: str):
    """Enrichit avec VirusTotal v3 sur le hash SHA256."""
    api_key = VT_API_KEY
    if not api_key:
        return {
            "enabled": False,
            "error": "Clé API non définie"
        }
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            reputation = attr.get("reputation", None)
            return {
                "enabled": True,
                "found": True,
                "last_analysis_stats": stats,
                "reputation": reputation,
                "harmless": stats.get("harmless"),
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "undetected": stats.get("undetected"),
            }
        elif resp.status_code == 404:
            return {"enabled": True, "found": False}
        else:
            return {
                "enabled": True,
                "error": f"HTTP {resp.status_code}",
                "body": resp.text[:200]
            }
    except Exception as e:
        return {
            "enabled": True,
            "error": str(e)
        }


def enrich_with_otx(sha256: str):
    api_key = OTX_API_KEY
    if not api_key:
        return {
            "enabled": False,
            "error": "Clé API non définie"
        }
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            reputation = attr.get("reputation", None)
            return {
                "enabled": True,
                "found": True,
                "last_analysis_stats": stats,
                "reputation": reputation,
                "harmless": stats.get("harmless"),
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "undetected": stats.get("undetected"),
            }
        elif resp.status_code == 404:
            return {"enabled": True, "found": False}
        else:
            return {
                "enabled": True,
                "error": f"HTTP {resp.status_code}",
                "body": resp.text[:200]
            }
    except Exception as e:
        return {
            "enabled": True,
            "error": str(e)
        }


#  ANALYSE GLOBALE
def analyze_file(path, use_vt=False, use_otx=False):
    """Analyse globale du fichier et retourne un dict exploitable en JSON."""
    result = {}
    # Hashs
    hashes = compute_hashes(path)
    result["hashes"] = hashes
    # Strings
    strings = extract_ascii_strings(path)
    result["strings_count"] = len(strings)
    # IOC
    result["iocs"] = extract_iocs(strings)
    # PE analysis
    result["pe_info"] = analyze_pe(path)
    sha256 = hashes["sha256"]
    # Enrichissement VirusTotal
    if use_vt:
        result["virustotal"] = enrich_with_virustotal(sha256)
    # Enrichissement OTX
    if use_otx:
        result["otx"] = enrich_with_otx(sha256)
    # Toujours renvoyer le résultat, même sans VT/OTX
    return result


def main():
    parser = argparse.ArgumentParser(description="Malware IOC Analyzer")
    parser.add_argument("path", help="Chemin du fichier à analyser")
    parser.add_argument(
        "--vt",
        action="store_true",
        help="Enrichissement VirusTotal sur le SHA256"
    )
    parser.add_argument(
        "--otx",
        action="store_true",
        help="Enrichissement OTX (clé OTX_API_KEY)"
    )
    args = parser.parse_args()
    # Normalisation du chemin (utile avec .. et chemins Windows)
    path = os.path.normpath(args.path)
    if not os.path.isfile(path):
        print(json.dumps(
            {"error": f"Fichier introuvable : {path}"},
            ensure_ascii=False
        ))
        sys.exit(1)
    try:
        result = analyze_file(path, use_vt=args.vt, use_otx=args.otx)
        if result is None:
            # Sécurité au cas où quelqu'un modifie analyze_file plus tard
            print(json.dumps(
                {"error": "analyze_file a retourné None (bug interne)"},
                ensure_ascii=False
            ))
            sys.exit(1)

        print(json.dumps(result, indent=4, ensure_ascii=False))
    except Exception as e:
        # Dernier filet de sécurité
        print(json.dumps(
            {"error": str(e)},
            ensure_ascii=False
        ))
        sys.exit(1)


if __name__ == "__main__":
    main()
