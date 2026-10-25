"""Courbe de tons du pilote Brother, mesurée sur une paire brut / BMP (étape 4c).

Le pilote Brother éclaircit l'image sur le PC : le brut 144 devient environ 244
(docs/protocole.md §5). Il n'existe aucune spécification de cette courbe ; on la
mesure donc sur les captures, en mettant chaque point du BMP du pilote en face du
point brut d'où il vient. Le décalage entre les deux a été mesuré par
`image_brute.py comparer` (étapes 3b, 4a, 4b) et se passe en paramètre.

Pour chaque valeur brute v (0 à 255), on garde la médiane des valeurs que le BMP
donne aux points bruts de valeur v. Pourquoi la médiane et pas la moyenne : au
bord d'un trait, un point peut tomber d'un côté dans le brut et de l'autre dans
le BMP (redressement, arrondi) ; ces paires aberrantes déplacent la moyenne, pas
la médiane. On affiche aussi l'écart interquartile, qui dit si une seule courbe
suffit (écart faible) ou si le pilote corrige aussi selon la colonne (écart fort).

Usage :
  py banc/courbe_tons.py mesurer BRUT BMP --dx 4 --dy 11 [--miroir] [--colonnes-paires]
                         [--plan 1] [--canal 0] > MESURE.txt
  py banc/courbe_tons.py combiner MESURE1.txt MESURE2.txt ...
  plan : 0 rouge, 1 vert, 2 bleu du brut ; canal : indice dans le BMP
  (gris : 0 ; couleur : 0 bleu, 1 vert, 2 rouge, ordre du BMP).
« combiner » relit ces sorties et rend la courbe complète de 256 valeurs
(docs/courbe-gris.txt) ; elle ne contient que des nombres et va dans le dépôt.
"""

import argparse
import math
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from image_brute import LARGEUR, Bmp, Brut  # noqa: E402


def mesurer(brut, bmp, dx, dy, miroir, colonnes_paires, plan, canal, pas_y=1):
    """Renvoie, pour chaque valeur brute, l'histogramme des valeurs du BMP."""
    histos = [[0] * 256 for _ in range(256)]
    pas_x = 2 if colonnes_paires else 1
    largeur = bmp.largeur // pas_x
    for y in range(0, bmp.hauteur, pas_y):
        yb = y + dy
        if not 0 <= yb < brut.lignes:
            continue  # sous la feuille, le pilote complète avec son propre fond
        ligne = brut.plan(yb, plan)
        if miroir:
            ligne = ligne[::-1]
        for x in range(largeur):
            xb = x + dx
            if 0 <= xb < LARGEUR:
                histos[ligne[xb]][bmp.point(x * pas_x, y, canal)] += 1
    return histos


def quantile(histo, q):
    total = sum(histo)
    cible, cumul = q * (total - 1), 0
    for v, n in enumerate(histo):
        cumul += n
        if cumul > cible:
            return v
    return 255


EFFECTIF_MINI = 1000  # en dessous, une médiane est trop sensible aux paires aberrantes
DEBUT_AJUSTEMENT = 64  # plus petite valeur brute retenue pour ajuster la loi de puissance


# Une ligne de « mesurer ». Pourquoi une expression régulière plutôt qu'un
# découpage par blancs : les quartiles s'écrivent « 90- 94 » quand le second a
# deux chiffres, ce qui changeait le nombre de champs ; à l'étape 4c, ces lignes
# étaient écartées sans bruit (bruts 40 à 44 notamment, relecture de fond).
LIGNE_MESURE = re.compile(r"^\s*(\d+)\s+médiane\s+(\d+)\s+quartiles\s+(\d+)\s*-\s*(\d+)\s+effectif\s+(\d+)\s*$")


def lire_mesure(chemin):
    """Relit la sortie de « mesurer » : {valeur brute: (médiane, effectif)}.
    Toute ligne non vide qui n'a pas la forme attendue arrête le programme."""
    table = {}
    with open(chemin, encoding="utf-8") as f:
        for numero, ligne in enumerate(f, 1):
            if not ligne.strip():
                continue
            m = LIGNE_MESURE.match(ligne)
            if not m:
                raise SystemExit(f"{chemin}:{numero} : ligne inattendue : {ligne.strip()!r}")
            table[int(m[1])] = (int(m[2]), int(m[5]))
    if not table:
        raise SystemExit(f"{chemin} : aucune mesure")
    return table


def combiner(chemins):
    """Fusionne plusieurs mesures en une courbe de 256 valeurs.

    Pour chaque valeur brute, on prend la médiane des médianes des scans,
    pondérée par leurs effectifs (les scans gris s'accordent à ±1 près, étape 4c),
    à condition que l'effectif total atteigne EFFECTIF_MINI. Ailleurs (noirs
    profonds, et au-dessus du blanc du papier, que le scanner ne rend jamais
    au-delà de 177 environ), on prolonge par une loi de puissance
    255 · (v / 255) ^ g, dont g est ajusté par moindres carrés sur les logarithmes
    des valeurs mesurées. Pourquoi cette forme : elle colle aux mesures à 1,1 niveau près
    sur toute la plage mesurée (déduit à l'étape 4c), et elle fixe 0 → 0 et
    255 → 255 sans paramètre de plus. Pourquoi pas une extrapolation linéaire du
    dernier tronçon : elle dépasserait 255 avant v = 255 ou n'y arriverait pas,
    selon le tronçon choisi. Les valeurs ajustées sont marquées comme telles."""
    mesures = [lire_mesure(c) for c in chemins]
    mesure = {}
    for v in range(256):
        points = sorted((m[v][0], m[v][1]) for m in mesures if v in m)
        total = sum(n for _, n in points)
        if total >= EFFECTIF_MINI:
            cumul = 0
            for med, n in points:
                cumul += n
                if 2 * cumul >= total:
                    mesure[v] = (med, total)
                    break
    num = den = 0.0
    for v, (med, _) in mesure.items():
        # Ajustement sur les tons moyens et clairs seulement : la loi ne sert
        # qu'à prolonger la mesure au-dessus du blanc du papier, et les noirs
        # profonds (fond hors de la feuille, valeurs rendues très espacées)
        # tirent l'exposant sans rien dire de cette région.
        if DEBUT_AJUSTEMENT <= v < 255 and 0 < med < 255:
            x, y = math.log(v / 255), math.log(med / 255)
            num, den = num + x * y, den + x * x
    g = num / den
    courbe = []
    for v in range(256):
        if v in mesure:
            courbe.append((v, mesure[v][0], "mesuré", mesure[v][1]))
        else:
            # Une valeur ajustée ne descend jamais sous la précédente : au raccord
            # avec la mesure (brut 177 → 209 mesuré, 178 → 208 ajusté), la loi
            # passe un niveau sous la médiane, et une courbe de tons qui
            # redescend inverserait deux gris voisins.
            sortie = round(255 * (v / 255) ** g)
            if courbe:
                sortie = max(sortie, courbe[-1][1])
            courbe.append((v, sortie, "ajusté", 0))
    return g, courbe


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sous = ap.add_subparsers(dest="action", required=True)
    a = sous.add_parser("mesurer", help="courbe d'une paire brut / BMP")
    a.add_argument("brut")
    a.add_argument("bmp")
    a.add_argument("--dx", type=int, required=True)
    a.add_argument("--dy", type=int, required=True)
    a.add_argument("--miroir", action="store_true", help="verso : brut lu de droite à gauche")
    a.add_argument("--colonnes-paires", action="store_true", help="BMP à 600 ppp")
    a.add_argument("--plan", type=int, default=1, help="plan du brut (défaut : vert)")
    a.add_argument("--canal", type=int, default=0, help="canal du BMP (défaut : 0)")
    a.add_argument("--pas-y", type=int, default=1, help="une ligne sur N (plus rapide)")
    c = sous.add_parser("combiner", help="fusionner des mesures en une courbe de 256 valeurs")
    c.add_argument("mesures", nargs="+", help="sorties de « mesurer »")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if args.action == "combiner":
        g, courbe = combiner(args.mesures)
        print(f"# loi de puissance ajustée : 255 * (v / 255) ^ {g:.4f}")
        for v, sortie, origine, n in courbe:
            print(f"{v:3} {sortie:3} {origine} {n}")
        return 0

    brut, bmp = Brut(args.brut), Bmp(args.bmp)
    histos = mesurer(brut, bmp, args.dx, args.dy, args.miroir, args.colonnes_paires,
                     args.plan, args.canal, args.pas_y)
    for v, h in enumerate(histos):
        n = sum(h)
        if n:
            q1, med, q3 = quantile(h, .25), quantile(h, .5), quantile(h, .75)
            print(f"{v:3}  médiane {med:3}  quartiles {q1:3}-{q3:3}  effectif {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
