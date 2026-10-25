"""Extrait d'une capture les octets d'image lus par 0xC3 (docs/protocole.md §4).

Rejoue, hors ligne, la boucle de lecture du pilote Brother : pour chaque réponse
« bloc d'image prêt » (0xC5, sélecteur 02 02 02), on garde l'adresse et le volume
annoncés, puis on recolle, dans l'ordre, les données des lectures 0xC3 qui suivent.
Le résultat est un fichier brut, les blocs bout à bout, avec un petit index des
blocs sur la sortie standard.

Le fichier brut contient l'image d'un document : il s'écrit hors du dépôt
(CLAUDE.md), en pratique dans C:\\Users\\morva\\ds720d-captures\\images\\.

Pourquoi relire le pcap ici plutôt que la trace texte de l'analyseur : la trace
coupe les données à 32 octets par ligne, et la trace complète (--octets -1) ferait
plus de 30 Mo de texte pour 10 Mo d'image. On réutilise en revanche la lecture du
pcap et de l'en-tête USBPcap de l'analyseur, déjà contre-vérifiée par tshark.

Usage :
  py banc/extrait_image.py CAPTURE.pcap --adresse 15 SORTIE.brut
  py banc/extrait_image.py CAPTURE.pcap --adresse 15 SORTIE.brut --recto-verso
      (un fichier par page et par face : SORTIE-p1-recto.brut, SORTIE-p1-verso.brut…)
Code de sortie : 0 si chaque bloc a été lu en entier depuis l'adresse annoncée.
"""

import argparse
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyse_capture import (CBW, OP_LECTURE_TAMPON, OP_TUNNEL, TRANSFERT_BULK,  # noqa: E402
                             decoder_usbpcap, lire_pcap)

SELECTEUR_BLOC = b"\x02\x02\x02"  # réponse « bloc d'image », docs/protocole.md §2
ETAT_PRET = 1
ETAT_FIN_PAGE = 3


class Sorties:
    """Choisit le fichier où va chaque bloc.

    Sans recto-verso, tous les blocs vont bout à bout dans un seul fichier, comme
    avant. En recto-verso, le scanner alterne un bloc de la face avant et un bloc
    de la face arrière, en commençant par l'avant (étape 4a, docs/protocole.md §5 :
    blocs pairs contre les BMP 1 et 3 du pilote, impairs contre 2 et 4, sur
    `1e-gris-300-recto-verso`). Rien dans la réponse « bloc prêt » ne dit la face
    (ses mots 1 et 2 valent 1 et 0 partout) : seul le rang du bloc dans la page la
    donne. On écrit donc un fichier par page et par face, NOM-pN-recto.brut et
    NOM-pN-verso.brut, avec les octets tels que le scanner les envoie : le verso
    reste vu en miroir, le redresser relève du rendu (étape 4c), pas de l'extraction."""

    def __init__(self, chemin, recto_verso):
        self.chemin = Path(chemin)
        self.recto_verso = recto_verso
        self.fichiers = {}
        self.noms = []

    def fichier(self, page, rang):
        cle = (page, rang % 2) if self.recto_verso else None
        if cle not in self.fichiers:
            if self.recto_verso:
                nom = self.chemin.with_name(
                    f"{self.chemin.stem}-p{page + 1}-{'verso' if rang % 2 else 'recto'}{self.chemin.suffix}")
            else:
                nom = self.chemin
            self.fichiers[cle] = open(nom, "xb")  # « x » : ne jamais écraser une extraction
            self.noms.append(str(nom))
        return self.fichiers[cle]

    def fermer(self):
        for f in self.fichiers.values():
            f.close()


def extraire(chemin, adresse, sorties):
    """Écrit les blocs dans les fichiers de sorties et renvoie la liste (adresse,
    volume annoncé, volume lu, écarts, page, rang dans la page) de chaque bloc."""
    blocs = []
    cdb_en_cours = None   # CDB du dernier CBW de l'appareil
    bloc = None           # [adresse annoncée, volume annoncé, octets lus, prochaine adresse, écarts, page, rang]
    lecture = None        # adresse de la lecture 0xC3 en cours
    page, rang = 0, 0     # page courante (l'état « fin de page » la fait avancer), rang du prochain bloc
    for trame in lire_pcap(chemin):
        p = decoder_usbpcap(trame)
        if p is None or p.adresse != adresse or p.transfert != TRANSFERT_BULK:
            continue
        d = p.donnees
        if not p.endpoint & 0x80 and not p.retour and len(d) == CBW.size and d[:4] == b"USBC":
            cdb = CBW.unpack(d)[6][:d[14]]
            cdb_en_cours = cdb
            if cdb[0] == OP_LECTURE_TAMPON and len(cdb) == 16:
                lecture = struct.unpack(">I", cdb[2:6])[0]
            continue
        if not (p.endpoint & 0x80 and p.retour and d) or d[:4] == b"USBS" and len(d) == 13:
            continue  # pas une complétion de données IN (ou c'est un CSW)
        if p.tronque:
            raise SystemExit(f"trame {trame.numero} tronquée à la capture : image incomplète")
        if (cdb_en_cours and cdb_en_cours[0] == OP_TUNNEL and cdb_en_cours[10:13] == SELECTEUR_BLOC
                and len(d) == 24):
            etat, _, _, a, b, adr = struct.unpack("<6I", d)
            if etat == ETAT_PRET:
                if bloc:
                    blocs.append(bloc)
                bloc = [adr, a * b, 0, adr, 0, page, rang]
                rang += 1
            elif etat == ETAT_FIN_PAGE and rang:
                page, rang = page + 1, 0
        elif cdb_en_cours and cdb_en_cours[0] == OP_LECTURE_TAMPON and bloc and lecture is not None:
            if lecture != bloc[3]:
                bloc[4] += 1
            sorties.fichier(bloc[5], bloc[6]).write(d)
            bloc[2] += len(d)
            bloc[3] = lecture + len(d)
            lecture = None
    if bloc:
        blocs.append(bloc)
    return blocs


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("capture")
    ap.add_argument("--adresse", type=int, required=True)
    ap.add_argument("sortie", help="fichier brut à écrire (hors du dépôt)")
    ap.add_argument("--recto-verso", action="store_true",
                    help="un fichier par page et par face (NOM-pN-recto/verso)")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    sorties = Sorties(args.sortie, args.recto_verso)
    try:
        blocs = extraire(args.capture, args.adresse, sorties)
    finally:
        sorties.fermer()
    total = sum(b[2] for b in blocs)
    defauts = 0
    for i, (adr, annonce, lu, _, ecarts, page, rang) in enumerate(blocs):
        ok = lu == annonce and not ecarts
        defauts += not ok
        face = f"  page {page + 1} {'verso' if rang % 2 else 'recto'}" if args.recto_verso else ""
        print(f"bloc {i:3}  adresse 0x{adr:08X}  annoncé {annonce:>7} o  lu {lu:>7} o{face}"
              f"{'' if ok else '  !! incomplet ou discontinu'}")
    if args.recto_verso:
        for page in sorted({b[5] for b in blocs}):
            n = sum(1 for b in blocs if b[5] == page)
            if n % 2:  # chaque page porte autant de blocs recto que verso
                defauts += 1
                print(f"!! page {page + 1} : {n} blocs, nombre impair en recto-verso")
    print(f"# {len(blocs)} blocs, {total} o écrits dans {', '.join(sorties.noms)}, {defauts} défaut(s)")
    return 0 if defauts == 0 and blocs else 1


if __name__ == "__main__":
    sys.exit(main())
