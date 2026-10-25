"""Vérifie un PNG ou un PGM écrit par out\\convertir.exe contre l'image brute d'origine.

Arbitre extérieur, comme tshark pour l'analyseur : le PNG est relu chunk par
chunk à la main, mais les sommes de contrôle et la décompression passent par le
module zlib de Python, une implémentation indépendante de celle de src/image.c.
On contrôle la signature, la structure des chunks et leurs CRC-32, l'en-tête
IHDR, le flux zlib (Adler-32 compris, vérifié par zlib.decompress), le filtre de
chaque ligne, puis on compare chaque point au plan vert (gris) ou aux trois
plans (couleur) du fichier brut.

Usage :
  py banc/verif_png.py IMAGE.png BRUT
  py banc/verif_png.py IMAGE.pgm BRUT
Code de sortie : 0 si l'image est conforme et identique au brut.
"""

import struct
import sys
import zlib

LARGEUR = 2592
OCTETS_LIGNE = 3 * LARGEUR


def plans(brut, y):
    debut = y * OCTETS_LIGNE
    return (brut[debut:debut + LARGEUR], brut[debut + LARGEUR:debut + 2 * LARGEUR],
            brut[debut + 2 * LARGEUR:debut + 3 * LARGEUR])


def verifier_png(image, brut):
    if image[:8] != b"\x89PNG\r\n\x1a\n":
        return ["signature PNG absente"]
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
    if l != LARGEUR or prof != 8 or canaux is None or comp or filtre or entrelace:
        return erreurs + [f"IHDR inattendu : {l} × {h}, profondeur {prof}, couleur {couleur}"]
    flux = b"".join(d for t, d in chunks if t == b"IDAT")
    donnees = zlib.decompress(flux)  # lève une exception si l'Adler-32 est faux
    pas = 1 + LARGEUR * canaux
    if len(donnees) != pas * h or h * OCTETS_LIGNE != len(brut):
        return erreurs + [f"{len(donnees)} o décompressés pour {h} lignes, brut de {len(brut)} o"]
    for y in range(h):
        ligne = donnees[y * pas:(y + 1) * pas]
        r, v, b = plans(brut, y)
        if ligne[0] != 0:
            erreurs.append(f"ligne {y} : filtre {ligne[0]}")
        attendu = v if canaux == 1 else bytes(o for trio in zip(r, v, b) for o in trio)
        if ligne[1:] != attendu:
            erreurs.append(f"ligne {y} : points différents du brut")
        if len(erreurs) > 10:
            break
    print(f"PNG {l} × {h}, {'couleur' if canaux == 3 else 'gris'}, chunks {[t.decode() for t in types]}, "
          f"{len(flux)} o de flux zlib")
    return erreurs


def verifier_pgm(image, brut):
    entete = b"P5\n%d %d\n255\n" % (LARGEUR, len(brut) // OCTETS_LIGNE)
    if not image.startswith(entete):
        return [f"en-tête PGM inattendu : {image[:20]!r}"]
    points = image[len(entete):]
    attendu = b"".join(plans(brut, y)[1] for y in range(len(brut) // OCTETS_LIGNE))
    print(f"PGM {LARGEUR} × {len(brut) // OCTETS_LIGNE}")
    return [] if points == attendu else ["points différents du plan vert du brut"]


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    with open(sys.argv[1], "rb") as f:
        image = f.read()
    with open(sys.argv[2], "rb") as f:
        brut = f.read()
    erreurs = verifier_pgm(image, brut) if image[:2] == b"P5" else verifier_png(image, brut)
    for e in erreurs:
        print("  !!", e)
    print("conforme" if not erreurs else f"{len(erreurs)} écart(s)")
    return 0 if not erreurs else 1


if __name__ == "__main__":
    sys.exit(main())
