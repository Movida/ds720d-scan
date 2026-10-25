"""Image brute du DS-720D : conversion en BMP et comparaison au BMP du pilote Brother.

Format des données lues par 0xC3, établi à l'étape 3b (docs/protocole.md §5) :
une ligne de balayage fait 3 × 2 592 octets, un plan par couleur, dans l'ordre
rouge, vert, bleu ; 8 bits par échantillon, pas d'en-tête ni de bourrage. Un bloc
de 622 080 o porte donc 80 lignes, et 2 592 points font les 8,64 po de la
fenêtre à 300 ppp.

Deux usages :
  py banc/image_brute.py bmp BRUT SORTIE.bmp [--gris]
      écrit un BMP 24 bits (ou 8 bits en gris, plan vert seul) à partir d'un
      fichier brut de banc/extrait_image.py, sans aucune retouche des valeurs ;
  py banc/image_brute.py comparer BRUT REFERENCE.bmp
      cherche le décalage qui aligne le brut sur le BMP produit par le pilote
      TWAIN pendant la même capture, puis mesure la corrélation de chaque plan
      avec chaque canal du BMP.

Les fichiers brut et BMP contiennent l'image d'un document : ils restent hors du
dépôt (CLAUDE.md), dans C:\\Users\\morva\\ds720d-captures\\images\\.

Pourquoi BMP et pas PGM/PNG ici : c'est un outil de banc, et Windows ouvre un BMP
sans rien installer. Le PGM puis le PNG faits main viendront en C à l'étape 3f ;
cet outil servira alors de référence pour les comparer. Pourquoi la corrélation
et pas l'égalité des octets : le pilote Brother applique sur le PC une courbe de
tons (le brut 144 devient environ 244), on ne peut donc comparer que la forme de
l'image, pas ses valeurs.
"""

import argparse
import math
import random
import struct
import sys

LARGEUR = 2592                  # points par ligne et par plan
PLANS = ("rouge", "vert", "bleu")
OCTETS_LIGNE = LARGEUR * len(PLANS)


class Brut:
    """Accès aux échantillons d'un fichier brut, ligne par ligne."""

    def __init__(self, chemin):
        with open(chemin, "rb") as f:
            self.octets = f.read()
        if len(self.octets) % OCTETS_LIGNE:
            raise SystemExit(f"{chemin} : {len(self.octets)} o, pas un multiple de {OCTETS_LIGNE}")
        self.lignes = len(self.octets) // OCTETS_LIGNE

    def plan(self, y, p):
        debut = y * OCTETS_LIGNE + p * LARGEUR
        return self.octets[debut:debut + LARGEUR]

    def point(self, x, y, p):
        return self.octets[y * OCTETS_LIGNE + p * LARGEUR + x]


def ecrire_bmp(brut, chemin, gris):
    """BMP Windows (BITMAPINFOHEADER, non compressé). Lignes de bas en haut,
    chacune bourrée à un multiple de 4 octets ; en 24 bits, l'ordre est B, V, R.
    En gris, une palette de 256 niveaux et le seul plan vert (c'est lui que suit
    le gris du pilote Brother : corrélation 0,985 sur 2a, contre 0,814 pour le rouge)."""
    oc = 1 if gris else 3
    pas = (LARGEUR * oc + 3) // 4 * 4
    palette = b"".join(bytes((v, v, v, 0)) for v in range(256)) if gris else b""
    debut = 14 + 40 + len(palette)
    taille = debut + pas * brut.lignes
    with open(chemin, "xb") as f:  # « x » : jamais écraser
        f.write(b"BM" + struct.pack("<IHHI", taille, 0, 0, debut))
        f.write(struct.pack("<IiiHHIIiiII", 40, LARGEUR, brut.lignes, 1, oc * 8, 0,
                            pas * brut.lignes, 11811, 11811, 256 if gris else 0, 0))  # 300 ppp
        f.write(palette)
        bourrage = bytes(pas - LARGEUR * oc)
        for y in range(brut.lignes - 1, -1, -1):
            if gris:
                f.write(brut.plan(y, 1))
            else:
                r, v, b = brut.plan(y, 0), brut.plan(y, 1), brut.plan(y, 2)
                ligne = bytearray(LARGEUR * 3)
                ligne[0::3], ligne[1::3], ligne[2::3] = b, v, r
                f.write(ligne)
            f.write(bourrage)


class Bmp:
    """Lecture d'un BMP 8 ou 24 bits non compressé (celui du pilote TWAIN)."""

    def __init__(self, chemin):
        with open(chemin, "rb") as f:
            self.octets = f.read()
        if self.octets[:2] != b"BM":
            raise SystemExit(f"{chemin} : pas un BMP")
        self.debut = struct.unpack_from("<I", self.octets, 10)[0]
        self.largeur, h = struct.unpack_from("<ii", self.octets, 18)
        bits, compression = struct.unpack_from("<HI", self.octets, 28)
        if bits not in (8, 24) or compression:
            raise SystemExit(f"{chemin} : BMP {bits} bits compression {compression} non géré")
        self.de_bas_en_haut, self.hauteur = h > 0, abs(h)
        self.oc = bits // 8
        self.pas = (self.largeur * self.oc + 3) // 4 * 4
        self.canaux = ("bleu", "vert", "rouge") if self.oc == 3 else ("gris",)

    def point(self, x, y, c):
        """y compté depuis le haut ; c indice dans self.canaux."""
        ligne = self.hauteur - 1 - y if self.de_bas_en_haut else y
        return self.octets[self.debut + ligne * self.pas + x * self.oc + c]


def correlation(a, b):
    """Coefficient de Pearson : 1 si b est une fonction affine croissante de a."""
    ma, mb = sum(a) / len(a), sum(b) / len(b)
    sa = math.sqrt(sum((v - ma) ** 2 for v in a))
    sb = math.sqrt(sum((v - mb) ** 2 for v in b))
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / (sa * sb) if sa and sb else 0.0


def comparer(brut, bmp, echantillon=4000):
    """Cherche (dx, dy) tel que BMP(x, y) ≈ brut(x + dx, y + dy), plan vert contre
    canal vert (ou gris), sur des points tirés au hasard (graine fixe : résultat
    reproductible), puis corrèle chaque plan avec chaque canal à ce décalage."""
    marge = 64
    hauteur = min(brut.lignes, bmp.hauteur) - marge
    if bmp.largeur > LARGEUR or hauteur <= marge:
        raise SystemExit("images trop petites ou incompatibles")
    hasard = random.Random(3)
    points = [(hasard.randrange(marge, bmp.largeur - marge), hasard.randrange(marge, hauteur))
              for _ in range(echantillon)]
    canal_ref = 1 if bmp.oc == 3 else 0

    def score(dx, dy, pts):
        ref = [bmp.point(x, y, canal_ref) for x, y in pts]
        return correlation(ref, [brut.point(x + dx, y + dy, 1) for x, y in pts])

    # Le pic de corrélation est étroit (0,9987 au bon décalage de la photo couleur,
    # 0,992 à une ligne près) et le bruit d'échantillonnage le cache sur une grille
    # grossière. D'où une recherche exhaustive sur peu de points, puis un nouveau
    # classement des 20 meilleurs candidats sur tout l'échantillon.
    candidats = sorted(
        ((score(dx, dy, points[:800]), dx, dy)
         for dy in range(-marge + 1, marge) for dx in range(0, LARGEUR - bmp.largeur + 1)),
        reverse=True)[:20]
    r, dx, dy = max((score(dx, dy, points), dx, dy) for _, dx, dy in candidats)
    print(f"décalage : BMP(x, y) = brut(x + {dx}, y + {dy}), corrélation vert {r:.4f}")
    print(f"brut {LARGEUR} × {brut.lignes}, BMP {bmp.largeur} × {bmp.hauteur}")
    for p, nom in enumerate(PLANS):
        valeurs = [brut.point(x + dx, y + dy, p) for x, y in points]
        cor = ", ".join(f"{c} {correlation([bmp.point(x, y, i) for x, y in points], valeurs):.3f}"
                        for i, c in enumerate(bmp.canaux))
        print(f"  plan {p} ({nom}) : {cor}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sous = ap.add_subparsers(dest="action", required=True)
    a = sous.add_parser("bmp", help="brut vers BMP, valeurs inchangées")
    a.add_argument("brut")
    a.add_argument("sortie")
    a.add_argument("--gris", action="store_true", help="BMP 8 bits, plan vert seul")
    c = sous.add_parser("comparer", help="aligner et corréler avec le BMP du pilote Brother")
    c.add_argument("brut")
    c.add_argument("reference")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    brut = Brut(args.brut)
    if args.action == "bmp":
        ecrire_bmp(brut, args.sortie, args.gris)
        print(f"{args.sortie} : {LARGEUR} × {brut.lignes}, {'gris' if args.gris else 'couleur'}")
    else:
        comparer(brut, Bmp(args.reference))
    return 0


if __name__ == "__main__":
    sys.exit(main())
