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


def extraire(chemin, adresse, sortie):
    """Écrit les blocs dans sortie et renvoie la liste (adresse, volume annoncé,
    volume lu, écarts) de chaque bloc."""
    blocs = []
    cdb_en_cours = None   # CDB du dernier CBW de l'appareil
    bloc = None           # [adresse annoncée, volume annoncé, octets lus, prochaine adresse, écarts]
    lecture = None        # adresse de la lecture 0xC3 en cours
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
                bloc = [adr, a * b, 0, adr, 0]
        elif cdb_en_cours and cdb_en_cours[0] == OP_LECTURE_TAMPON and bloc and lecture is not None:
            if lecture != bloc[3]:
                bloc[4] += 1
            sortie.write(d)
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
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    with open(args.sortie, "xb") as f:  # « x » : ne jamais écraser une extraction
        blocs = extraire(args.capture, args.adresse, f)
    total = sum(b[2] for b in blocs)
    defauts = 0
    for i, (adr, annonce, lu, _, ecarts) in enumerate(blocs):
        ok = lu == annonce and not ecarts
        defauts += not ok
        print(f"bloc {i:3}  adresse 0x{adr:08X}  annoncé {annonce:>7} o  lu {lu:>7} o"
              f"{'' if ok else '  !! incomplet ou discontinu'}")
    print(f"# {len(blocs)} blocs, {total} o écrits dans {args.sortie}, {defauts} défaut(s)")
    return 0 if defauts == 0 and blocs else 1


if __name__ == "__main__":
    sys.exit(main())
