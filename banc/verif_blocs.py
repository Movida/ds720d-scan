"""Contrôle de la boucle de lecture d'image dans une trace décodée (docs/protocole.md §4).

Pour chaque réponse « bloc d'image : état 1 (prêt) » (sélecteur 02 02 02 de 0xC5),
vérifie que les lectures 0xC3 qui suivent partent de l'adresse annoncée, se suivent
sans trou et totalisent le produit des mots 3 et 4 de la réponse. C'est ce qui
permet de dire que l'état annonce bien le bloc que lit 0xC3.

La trace vient de banc/analyse_capture.py (capture du pilote Brother) ou, à partir
de l'étape 3e, de notre propre code : même format, même contrôle.

Usage :
  py banc/verif_blocs.py TRACE.txt [TRACE2.txt …]
Code de sortie : 0 si tous les blocs sont conformes, 1 sinon.
"""

import re
import sys

PRET = re.compile(r"bloc d'image : état 1 \(prêt\), (\d+) × (\d+) = (\d+) o, adresse 0x([0-9A-F]+)")
LECTURE = re.compile(r"lecture 0xC3 à l'adresse 0x([0-9A-F]+), (\d+) o")


def verifier(chemin):
    """Renvoie (blocs, écarts, facteurs vus) et affiche chaque écart."""
    blocs, ecarts, facteurs = 0, 0, set()
    attendu = None  # (adresse annoncée, volume annoncé) du bloc en cours
    suivante, total = 0, 0

    def clore():
        nonlocal ecarts
        if attendu and total != attendu[1]:
            ecarts += 1
            print(f"  bloc à 0x{attendu[0]:08X} : {total} o lus, {attendu[1]} annoncés")

    with open(chemin, encoding="utf-8-sig", errors="replace") as f:
        for ligne in f:
            m = PRET.search(ligne)
            if m:
                clore()
                attendu = (int(m[4], 16), int(m[3]))
                suivante, total = attendu[0], 0
                blocs += 1
                facteurs.add((int(m[1]), int(m[2])))
                continue
            m = LECTURE.search(ligne)
            if m and attendu:
                adresse, lg = int(m[1], 16), int(m[2])
                if adresse != suivante:
                    ecarts += 1
                    print(f"  lecture à 0x{adresse:08X}, attendue à 0x{suivante:08X}")
                suivante, total = adresse + lg, total + lg
    clore()
    return blocs, ecarts, facteurs


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    echec = False
    for chemin in sys.argv[1:]:
        blocs, ecarts, facteurs = verifier(chemin)
        texte = ", ".join(f"{a} × {b}" for a, b in sorted(facteurs)) or "aucun"
        print(f"{chemin} : {blocs} blocs, {ecarts} écarts, facteurs {texte}")
        echec |= ecarts > 0
    return 1 if echec else 0


if __name__ == "__main__":
    sys.exit(main())
