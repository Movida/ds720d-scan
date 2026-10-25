"""Vérifie un PNG ou un PGM écrit par out\\convertir.exe contre l'image brute d'origine.

Arbitre extérieur, comme tshark pour l'analyseur : le PNG est relu chunk par
chunk à la main, mais les sommes de contrôle et la décompression passent par le
module zlib de Python, une implémentation indépendante de celle de src/image.c.
On contrôle la signature, la structure des chunks et leurs CRC-32, l'en-tête
IHDR, le flux zlib (Adler-32 compris, vérifié par zlib.decompress), le filtre de
chaque ligne et le chunk pHYs, puis on compare chaque point à ce qu'il doit être :

- en mode --brut (convertir --brut), le plan vert (gris) ou les trois plans
  (couleur) du fichier brut, tels quels ;
- sinon, la page rendue, recalculée ici à partir du brut et de
  docs/courbe-gris.txt, sans rien reprendre de src/rendu.c : recadrage, verso
  retourné, courbe de tons, largeur doublée à 600 dpi (docs/protocole.md §5, §6).

Avec --bmp, on mesure en plus l'écart moyen entre l'image et le BMP du pilote
Brother pris pendant la même capture (gris : canal gris ; couleur : par canal),
sur la partie commune, au-dessus du fond que le pilote ajoute sous la feuille.

Usage :
  py banc/verif_png.py IMAGE.png BRUT [--brut] [--verso] [--ppp-y 600] [--bmp REF.bmp]
  py banc/verif_png.py IMAGE.pgm BRUT [--brut] [--verso] [--ppp-y 600]
Code de sortie : 0 si l'image est conforme et identique à l'attendu.
"""

import argparse
import struct
import sys
import zlib
from pathlib import Path

LARGEUR = 2592
OCTETS_LIGNE = 3 * LARGEUR
COURBE = Path(__file__).resolve().parent.parent / "docs" / "courbe-gris.txt"

# Géométrie mesurée sur les BMP du pilote (docs/protocole.md §5 et §6).
SAUT = {"recto": 11, "verso": 146}   # lignes à 300 ppp
POINTS = {300: 2548, 600: 2550}      # points bruts gardés


def lire_courbe():
    valeurs = [int(l.split()[1]) for l in COURBE.read_text(encoding="utf-8").splitlines()
               if l.strip() and not l.startswith("#")]
    if len(valeurs) != 256:
        raise SystemExit(f"{COURBE} : {len(valeurs)} valeurs au lieu de 256")
    return bytes(valeurs)


def plans(brut, y):
    debut = y * OCTETS_LIGNE
    return (brut[debut:debut + LARGEUR], brut[debut + LARGEUR:debut + 2 * LARGEUR],
            brut[debut + 2 * LARGEUR:debut + 3 * LARGEUR])


def attendu(brut, args, canaux):
    """Renvoie (largeur, hauteur, ppp_x, fonction ligne y → octets attendus)."""
    lignes = len(brut) // OCTETS_LIGNE
    if args.brut:
        def ligne(y):
            r, v, b = plans(brut, y)
            return v if canaux == 1 else bytes(o for trio in zip(r, v, b) for o in trio)
        return LARGEUR, lignes, 300, ligne

    courbe = lire_courbe()
    facteur = args.ppp_y // 300
    saut = SAUT["verso" if args.verso else "recto"] * facteur
    n = POINTS[args.ppp_y]
    # Recto : colonnes 4, 5… ; verso : 2 551, 2 550… (miroir). Un point de plus
    # pour le voisin de l'interpolation à 600 dpi.
    cols = [2551 - k for k in range(n + 1)] if args.verso else [4 + k for k in range(n + 1)]

    def ligne(y):
        p = plans(brut, y + saut)
        choisis = (p[1],) if canaux == 1 else p
        rendus = [[courbe[pl[c]] for c in cols] for pl in choisis]
        if facteur == 2:
            rendus = [[v for k in range(n) for v in (r[k], (r[k] + r[k + 1] + 1) // 2)] for r in rendus]
        else:
            rendus = [r[:n] for r in rendus]
        return bytes(o for trio in zip(*rendus) for o in trio)
    return n * facteur, lignes - saut, 300 * facteur, ligne


def lire_png(image):
    """Chunks contrôlés ; renvoie (erreurs, largeur, hauteur, canaux, pHYs, données)."""
    if image[:8] != b"\x89PNG\r\n\x1a\n":
        return ["signature PNG absente"], 0, 0, 0, None, b""
    erreurs, chunks, i = [], [], 8
    while i < len(image):
        lg, = struct.unpack(">I", image[i:i + 4])
        type_, donnees = image[i + 4:i + 8], image[i + 8:i + 8 + lg]
        crc, = struct.unpack(">I", image[i + 8 + lg:i + 12 + lg])
        if zlib.crc32(type_ + donnees) != crc:
            erreurs.append(f"CRC faux pour le chunk {type_!r}")
        chunks.append((type_, donnees))
        i += 12 + lg
    types = [t for t, _ in chunks]
    if types[0] != b"IHDR" or types[-1] != b"IEND":
        erreurs.append(f"ordre des chunks : {types}")
    l, h, prof, couleur, comp, filtre, entrelace = struct.unpack(">IIBBBBB", chunks[0][1])
    canaux = {0: 1, 2: 3}.get(couleur)
    if prof != 8 or canaux is None or comp or filtre or entrelace:
        erreurs.append(f"IHDR inattendu : profondeur {prof}, couleur {couleur}")
        return erreurs, l, h, 0, None, b""
    phys = next((struct.unpack(">IIB", d) for t, d in chunks if t == b"pHYs"), None)
    flux = b"".join(d for t, d in chunks if t == b"IDAT")
    donnees = zlib.decompress(flux)  # lève une exception si l'Adler-32 est faux
    print(f"PNG {l} × {h}, {'couleur' if canaux == 3 else 'gris'}, chunks {[t.decode() for t in types]}, "
          f"{len(flux)} o de flux zlib")
    pas = 1 + l * canaux
    if len(donnees) != pas * h:
        erreurs.append(f"{len(donnees)} o décompressés pour {h} lignes de {pas} o")
        return erreurs, l, h, canaux, phys, b""
    lignes = bytearray()
    for y in range(h):
        if donnees[y * pas] != 0:
            erreurs.append(f"ligne {y} : filtre {donnees[y * pas]}")
        lignes += donnees[y * pas + 1:(y + 1) * pas]
    return erreurs, l, h, canaux, phys, bytes(lignes)


def lire_pgm(image):
    champs = image.split(maxsplit=4)
    if champs[0] != b"P5" or champs[3] != b"255":
        return [f"en-tête PGM inattendu : {image[:20]!r}"], 0, 0, 0, None, b""
    l, h = int(champs[1]), int(champs[2])
    print(f"PGM {l} × {h}")
    return [], l, h, 1, None, image[len(image) - l * h:]


def ecart_bmp(points, l, h, canaux, chemin):
    """Écart absolu moyen avec le BMP du pilote, par canal, sur la partie commune."""
    d = Path(chemin).read_bytes()
    debut, = struct.unpack_from("<I", d, 10)
    lb, hb = struct.unpack_from("<ii", d, 18)
    oc = struct.unpack_from("<H", d, 28)[0] // 8
    pas = (lb * oc + 3) & ~3
    largeur, hauteur = min(l, lb), min(h, abs(hb))
    ordre = (0,) if oc == 1 else (2, 1, 0)  # BMP : bleu, vert, rouge ; PNG : rouge, vert, bleu
    sommes = [0] * canaux
    for y in range(hauteur):
        yb = abs(hb) - 1 - y if hb > 0 else y
        lb_ = d[debut + yb * pas:debut + yb * pas + largeur * oc]
        lp = points[y * l * canaux:(y * l + largeur) * canaux]
        for c in range(canaux):
            sommes[c] += sum(abs(a - b) for a, b in zip(lp[c::canaux], lb_[ordre[c]::oc]))
    n = largeur * hauteur
    noms = ("gris",) if canaux == 1 else ("rouge", "vert", "bleu")
    print(f"écart moyen avec {Path(chemin).name} sur {largeur} × {hauteur} : "
          + ", ".join(f"{nom} {s / n:.2f}" for nom, s in zip(noms, sommes)))


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("image")
    ap.add_argument("brut")
    ap.add_argument("--brut", dest="brut_seul", action="store_true", help="image produite par convertir --brut")
    ap.add_argument("--verso", action="store_true")
    ap.add_argument("--ppp-y", type=int, choices=(300, 600), default=300)
    ap.add_argument("--bmp", help="BMP du pilote Brother à comparer")
    args = ap.parse_args()
    args.brut, chemin_brut = args.brut_seul, args.brut
    if args.verso and (args.brut or args.ppp_y == 600):
        ap.error("--verso ne va ni avec --brut ni avec --ppp-y 600 (convertir les refuse aussi)")
    image = Path(args.image).read_bytes()
    brut = Path(chemin_brut).read_bytes()
    if len(brut) % OCTETS_LIGNE:
        raise SystemExit(f"{chemin_brut} : pas un nombre entier de lignes")

    pgm = image[:2] == b"P5"
    erreurs, l, h, canaux, phys, points = lire_pgm(image) if pgm else lire_png(image)
    if not erreurs:
        la, ha, ppp_x, ligne = attendu(brut, args, canaux)
        if (l, h) != (la, ha):
            erreurs.append(f"dimensions {l} × {h}, attendu {la} × {ha}")
        elif not pgm:
            ppm = lambda p: (p * 10000 + 127) // 254  # même arrondi que la spec : n / 0,0254 m
            if phys != (ppm(ppp_x), ppm(args.ppp_y), 1):
                erreurs.append(f"pHYs {phys}, attendu {(ppm(ppp_x), ppm(args.ppp_y), 1)}")
        if not erreurs:
            pas = l * canaux
            for y in range(h):
                if points[y * pas:(y + 1) * pas] != ligne(y):
                    erreurs.append(f"ligne {y} : points différents de l'attendu")
                    if len(erreurs) > 10:
                        break
    if args.bmp and not erreurs:
        ecart_bmp(points, l, h, canaux, args.bmp)
    for e in erreurs:
        print("  !!", e)
    print("conforme" if not erreurs else f"{len(erreurs)} écart(s)")
    return 0 if not erreurs else 1


if __name__ == "__main__":
    sys.exit(main())
