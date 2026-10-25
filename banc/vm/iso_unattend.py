"""Image ISO 9660 + Joliet écrite à la main, pour porter autounattend.xml dans la VM.

Usage : py -I banc/vm/iso_unattend.py FICHIER.xml SORTIE.iso

Pourquoi : l'installateur de Windows cherche « autounattend.xml » à la racine
de tous les supports amovibles (doc Microsoft « Windows Setup Automation
Overview », recherche implicite des fichiers de réponse). Un second lecteur
de CD dans la VM est le support le plus simple, mais Medabot n'a pas
`oscdimg` (il vient de l'ADK, non installé) : on écrit l'image nous-mêmes,
comme le PNG de l'étape 3.

Pourquoi Joliet : ISO 9660 niveau 1 n'admet que des noms 8.3 en majuscules
(« AUTOUNAT.XML »), que l'installateur ne reconnaîtrait pas. L'extension
Joliet (descripteur de volume supplémentaire, noms en UCS-2 gros-boutiste)
donne le nom long ; Windows la lit en priorité. Pourquoi pas le niveau 2
d'ISO 9660 (noms jusqu'à 31 caractères, « AUTOUNATTEND.XML;1 ») : il
suffirait sans doute, la recherche de Windows ignorant la casse, mais Joliet
est ce que produit oscdimg et le seul chemin vérifié (image montée sous
Windows, fichier relu identique).
Pourquoi pas une disquette FAT12 : la disquette virtuelle de VMware sous
firmware UEFI est mal documentée, le CD est sûr.

Sources : ECMA-119 (= ISO 9660), 2e édition, §6.7 et §8 (descripteurs), §9.1
(enregistrement de répertoire), §9.4 (table des chemins) ; spécification
Joliet (Microsoft, 1995) pour les séquences d'échappement « %/E » (UCS-2
niveau 3).

Disposition (secteurs de 2 048 o) :
  0-15  zone système (zéros)       16  descripteur primaire (PVD)
  17    supplémentaire Joliet (SVD) 18  terminateur
  19/20 tables des chemins L/M du PVD   21/22 tables L/M de Joliet
  23    répertoire racine du PVD   24  répertoire racine Joliet
  25-   données du fichier
"""

import struct
import sys
import time

SECTEUR = 2048


def deux_sens16(v):
    """Entier 16 bits dans les deux boutismes (ECMA-119 §7.2.3)."""
    return struct.pack("<H", v) + struct.pack(">H", v)


def deux_sens32(v):
    """Entier 32 bits dans les deux boutismes (ECMA-119 §7.3.3)."""
    return struct.pack("<I", v) + struct.pack(">I", v)


def date_repertoire(t):
    """Date de 7 octets d'un enregistrement de répertoire (§9.1.5), en UTC."""
    return bytes([t.tm_year - 1900, t.tm_mon, t.tm_mday,
                  t.tm_hour, t.tm_min, t.tm_sec, 0])


def date_volume(t):
    """Date de 17 octets d'un descripteur de volume (§8.4.26.1), en UTC."""
    return time.strftime("%Y%m%d%H%M%S", t).encode("ascii") + b"00" + b"\x00"


DATE_VIDE = b"0" * 16 + b"\x00"   # « non précisée » (§8.4.26.1)


def enregistrement(lba, taille, nom, repertoire, t):
    """Enregistrement de répertoire (§9.1), complété à une longueur paire."""
    corps = (b"\x00"                       # longueur des attributs étendus
             + deux_sens32(lba)            # emplacement de l'extent
             + deux_sens32(taille)         # longueur des données
             + date_repertoire(t)
             + bytes([0x02 if repertoire else 0x00])  # drapeaux : répertoire
             + b"\x00\x00"                 # unité de fichier, intervalle
             + deux_sens16(1)              # numéro de séquence du volume
             + bytes([len(nom)]) + nom)
    # Octet de remplissage (§9.1.12) quand la longueur du nom est paire : il
    # fait partie de l'enregistrement, donc LEN_DR (§9.1.1) le compte. Une
    # première version l'ajoutait après coup sans le compter (relecture de 5g) ;
    # sans conséquence avec un seul fichier, mais un second aurait été sauté.
    if len(nom) % 2 == 0:
        corps += b"\x00"
    rec = bytes([len(corps) + 1]) + corps
    assert rec[0] == len(rec) and len(rec) % 2 == 0
    return rec


def chaine(texte, longueur, joliet):
    """Champ texte complété d'espaces : ASCII, ou UCS-2 gros-boutiste en Joliet."""
    if joliet:
        b = texte.encode("utf-16-be")
        return (b + " ".encode("utf-16-be") * longueur)[:longueur]
    return texte.encode("ascii").ljust(longueur, b" ")[:longueur]


def descripteur(type_, joliet, nb_secteurs, lba_l, lba_m, racine, t):
    """Descripteur de volume primaire ou supplémentaire (§8.4 et §8.5)."""
    d = bytearray(SECTEUR)
    d[0] = type_
    d[1:6] = b"CD001"
    d[6] = 1                                    # version du descripteur
    d[8:40] = chaine("", 32, joliet)            # identifiant du système
    d[40:72] = chaine("DS720D_UNATTEND", 32, joliet)
    d[80:88] = deux_sens32(nb_secteurs)
    if joliet:
        d[88:91] = b"%/E"                       # Joliet, UCS-2 niveau 3
    d[120:124] = deux_sens16(1)                 # taille de l'ensemble
    d[124:128] = deux_sens16(1)                 # numéro dans l'ensemble
    d[128:132] = deux_sens16(SECTEUR)           # taille de bloc logique
    d[132:140] = deux_sens32(10)                # taille de la table des chemins
    d[140:144] = struct.pack("<I", lba_l)       # table L (petit-boutiste)
    d[148:152] = struct.pack(">I", lba_m)       # table M (gros-boutiste)
    d[156:190] = racine                         # répertoire racine, 34 o
    for debut, long_ in ((190, 128), (318, 128), (446, 128), (574, 128),
                         (702, 37), (739, 37), (776, 37)):
        d[debut:debut + long_] = chaine("", long_, joliet)
    d[813:830] = date_volume(t)                 # création
    d[830:847] = date_volume(t)                 # modification
    d[847:864] = DATE_VIDE                      # expiration
    d[864:881] = DATE_VIDE                      # effet
    d[881] = 1                                  # version de la structure
    return bytes(d)


def table_chemins(lba_racine, gros_boutiste):
    """Table des chemins réduite à la racine (§9.4) : 10 octets."""
    fmt = ">I" if gros_boutiste else "<I"
    fmt16 = ">H" if gros_boutiste else "<H"
    entree = (b"\x01\x00" + struct.pack(fmt, lba_racine)
              + struct.pack(fmt16, 1) + b"\x00\x00")
    return entree.ljust(SECTEUR, b"\x00")


def repertoire_racine(lba_racine, lba_fichier, taille, nom, t):
    """Racine : « . », « .. » (noms 0x00 et 0x01, §6.8.2.2) puis le fichier."""
    r = (enregistrement(lba_racine, SECTEUR, b"\x00", True, t)
         + enregistrement(lba_racine, SECTEUR, b"\x01", True, t)
         + enregistrement(lba_fichier, taille, nom, False, t))
    return r.ljust(SECTEUR, b"\x00")


def construire(donnees):
    t = time.gmtime()
    lba_pvd_racine, lba_j_racine, lba_fichier = 23, 24, 25
    nb_fichier = (len(donnees) + SECTEUR - 1) // SECTEUR
    total = lba_fichier + nb_fichier
    nom_pvd = b"AUTOUNAT.XML;1"                       # niveau 1 : 8.3 + version
    nom_joliet = "autounattend.xml".encode("utf-16-be")  # nom long, sans « ;1 »

    racine_pvd = enregistrement(lba_pvd_racine, SECTEUR, b"\x00", True, t)
    racine_j = enregistrement(lba_j_racine, SECTEUR, b"\x00", True, t)
    assert len(racine_pvd) == 34 and len(racine_j) == 34

    image = bytearray(SECTEUR * 16)
    image += descripteur(1, False, total, 19, 20, racine_pvd, t)
    image += descripteur(2, True, total, 21, 22, racine_j, t)
    term = bytearray(SECTEUR)
    term[0] = 255
    term[1:6] = b"CD001"
    term[6] = 1
    image += term
    image += table_chemins(lba_pvd_racine, False)
    image += table_chemins(lba_pvd_racine, True)
    image += table_chemins(lba_j_racine, False)
    image += table_chemins(lba_j_racine, True)
    image += repertoire_racine(lba_pvd_racine, lba_fichier, len(donnees),
                               nom_pvd, t)
    image += repertoire_racine(lba_j_racine, lba_fichier, len(donnees),
                               nom_joliet, t)
    image += donnees.ljust(nb_fichier * SECTEUR, b"\x00")
    assert len(image) == total * SECTEUR
    return bytes(image)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage : iso_unattend.py FICHIER.xml SORTIE.iso")
    with open(sys.argv[1], "rb") as f:
        donnees = f.read()
    image = construire(donnees)
    with open(sys.argv[2], "wb") as f:
        f.write(image)
    print(f"{sys.argv[2]} : {len(image)} o, {len(image) // SECTEUR} secteurs, "
          f"fichier de {len(donnees)} o")


if __name__ == "__main__":
    main()
