"""Compare deux traces au format commun (docs/format-trace.md).

Usage typique : la trace de référence vient de l'analyseur (capture du logiciel
Brother), l'autre de notre code C. On compare l'évènement et le détail de chaque
ligne ; les colonnes trame, temps et adresse sont ignorées, car elles ne peuvent
pas coïncider (numéros de trame Wireshark contre numéros d'ordre, horloges
différentes, WinUSB ne donne pas l'adresse USB).

Usage :
  py banc/compare_traces.py REFERENCE NOTRE [--sans-trames 19207-19213] [--sans-notre 11-14]
                            [--sans-tags]
Code de sortie : 0 si les traces concordent, 1 sinon.
"""

import argparse
import difflib
import re
import sys

# Ligne d'évènement : trame, temps, adresse, évènement, détail.
LIGNE = re.compile(r"^(\d+)\s+[\d.]+\s+\d+\s+(\S+)\s+(.*)$")
# Tag d'un CBW ou d'un CSW : choisi librement par l'hôte (BOT §5.1), il diffère
# forcément entre le pilote Brother et le nôtre.
TAG = re.compile(r"tag=0x[0-9A-F]{8}")


def lire(chemin, exclusions, sans_tags):
    """Renvoie la liste des lignes utiles, réduites à « évènement  détail »
    (ou « | détail » pour les lignes de détail)."""
    lignes = []
    exclue = False
    with open(chemin, encoding="utf-8-sig", errors="replace") as f:
        for brute in f:
            brute = brute.rstrip("\r\n")
            if not brute.strip() or brute.startswith("#"):
                continue
            m = LIGNE.match(brute)
            if m:
                trame = int(m.group(1))
                exclue = any(a <= trame <= b for a, b in exclusions)
                texte = f"{m.group(2)}  {m.group(3)}"
            elif brute.lstrip().startswith("|"):
                texte = brute.strip()  # détail : suit le sort de sa ligne
            else:
                texte = f"?? {brute.strip()}"  # ligne inattendue : on la garde pour la voir
                exclue = False
            if exclue:
                continue
            if sans_tags:
                texte = TAG.sub("tag=*", texte)
            lignes.append(texte)
    return lignes


def plage(texte):
    a, _, b = texte.partition("-")
    return int(a), int(b or a)


def main():
    ap = argparse.ArgumentParser(description="Compare deux traces au format commun.")
    ap.add_argument("reference", help="trace de référence (analyse_capture.py)")
    ap.add_argument("notre", help="trace de notre programme")
    ap.add_argument("--sans-trames", type=plage, action="append", default=[], metavar="A-B",
                    help="ignorer ces trames de la référence (répétable)")
    ap.add_argument("--sans-notre", type=plage, action="append", default=[], metavar="A-B",
                    help="ignorer ces numéros d'ordre de notre trace (répétable)")
    ap.add_argument("--sans-tags", action="store_true", help="ignorer les tags des CBW et CSW")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ref = lire(args.reference, args.sans_trames, args.sans_tags)
    notre = lire(args.notre, args.sans_notre, args.sans_tags)
    ecarts = list(difflib.unified_diff(ref, notre, "référence", "notre", lineterm="", n=1))
    print(f"# référence : {len(ref)} lignes, notre trace : {len(notre)} lignes")
    if not ref or not notre:
        # Deux traces vides « concordent » sans rien prouver : une capture qui n'a
        # rien vu (piège USBPcap après pnputil) doit faire échouer la comparaison.
        print("# échec : une des deux traces est vide")
        return 1
    if not ecarts:
        print("# concordance parfaite")
        return 0
    print("\n".join(ecarts))
    return 1


if __name__ == "__main__":
    sys.exit(main())
