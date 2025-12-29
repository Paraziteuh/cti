from app import *
from settings import *
from ioc import *

def main():
    parser = argparse.ArgumentParser(
        description="Analyse d'IOC (malware, PE, etc.)"
    )
    parser.add_argument("file", help="Fichier à analyser")
    parser.add_argument("-o", "--output", help="Fichier JSON en sortie", default=None)
    parser.add_argument("--vt", action="store_true",
                        help="Enrichir avec VirusTotal (nécessite une clé API virus total)")
    parser.add_argument("--otx", action="store_true",
                        help="Enrichir avec Alien Vault")
    args = parser.parse_args()
    path = args.file
    if not os.path.isfile(path):
        print(f"[ERREUR] Fichier introuvable : {path}")
        sys.exit(1)
    print(f"[+] Analyse de : {path}")
    report = analyze_file(path, use_vt=args.vt)
    if report is None:
        report = {"error": "analyze_file a retourné None (bug interne)"}
    json_report = json.dumps(report, indent=4)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(json_report)
        print(f"[+] Rapport enregistré : {args.output}")
    else:
        print(json_report)


if __name__ == "__main__":
    main()
