"""Analyseur de captures USBPcap, écrit à la main (bibliothèque standard seulement).

Lit un fichier .pcap produit par USBPcapCMD et décode, couche par couche :
  1. le format pcap (en-tête global, en-têtes d'enregistrement) ;
  2. l'en-tête USBPcap de chaque paquet (URB vu par le filtre USBPcap) ;
  3. les transferts de contrôle (paquet SETUP, USB 2.0 §9.3) et les descripteurs (§9.6) ;
  4. le transport Bulk-Only (CBW BOT §5.1, CSW BOT §5.2) et les commandes SCSI encapsulées ;
  5. le protocole vendeur du DS-720D : tunnel 0xC5, commandes de scanner SCSI-2
     emballées, lectures d'image 0xC3 (docs/protocole.md).

La sortie suit le « format de trace commun » (docs/format-trace.md) : c'est le même
format que produira notre propre code C, pour comparer les deux ligne à ligne.

Pourquoi un analyseur maison plutôt que tshark ou pyshark : le but du projet est
d'apprendre le protocole octet par octet. tshark reste l'arbitre extérieur
(banc/contre_verif.py compare nos résultats aux siens), mais il ne fait pas foi
à notre place. Pourquoi Python et pas C : c'est du banc de test, pas du code qui
parle au scanner, et Medabot n'a pas encore de compilateur C ; struct suffit à
lire des structures « packées » en petit-boutiste.

Usage :
  py banc/analyse_capture.py CAPTURE.pcap [--adresse 15] [--masquer 0xC5] [--octets 32]
  py banc/analyse_capture.py CAPTURE.pcap --resume
  py banc/analyse_capture.py CAPTURE.pcap --brut --de 19190 --a 19230
"""

import argparse
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# 1. Format pcap
#    Source : format libpcap (https://wiki.wireshark.org/Development/LibpcapFileFormat).
#    En-tête global de 24 octets, puis pour chaque paquet un en-tête de 16 octets
#    suivi des octets capturés.
# ---------------------------------------------------------------------------

PCAP_MAGIC_US = 0xA1B2C3D4  # horodatage en microsecondes
PCAP_MAGIC_NS = 0xA1B23C4D  # horodatage en nanosecondes
LINKTYPE_USBPCAP = 249      # type de lien attribué à USBPcap par tcpdump.org


@dataclass
class Trame:
    numero: int        # numéro à partir de 1, comme dans Wireshark
    temps: float       # secondes depuis la première trame du fichier
    longueur_origine: int
    donnees: bytes     # octets capturés (peut être plus court que l'origine)


def lire_pcap(chemin):
    """Générateur de Trame. Tolère un dernier enregistrement tronqué (arrêt brutal
    de USBPcapCMD) : il est signalé sur stderr et ignoré."""
    with open(chemin, "rb") as f:
        entete = f.read(24)
        if len(entete) < 24:
            raise ValueError("fichier trop court pour un en-tête pcap")
        # Le nombre magique dit l'ordre des octets : on essaie petit puis gros boutiste.
        for ordre in ("<", ">"):
            magique = struct.unpack(ordre + "I", entete[:4])[0]
            if magique in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
                break
        else:
            raise ValueError(f"pas un fichier pcap (magique {entete[:4].hex()}) ; pcapng non géré")
        diviseur = 1e6 if magique == PCAP_MAGIC_US else 1e9
        _, _, _, _, _, linktype = struct.unpack(ordre + "HHiIII", entete[4:])
        if linktype != LINKTYPE_USBPCAP:
            raise ValueError(f"type de lien {linktype}, attendu {LINKTYPE_USBPCAP} (USBPcap)")

        numero = 0
        t0 = None
        while True:
            rec = f.read(16)
            if not rec:
                return
            if len(rec) < 16:
                print(f"# avertissement : en-tête d'enregistrement tronqué après la trame {numero}",
                      file=sys.stderr)
                return
            sec, frac, incl, orig = struct.unpack(ordre + "IIII", rec)
            donnees = f.read(incl)
            if len(donnees) < incl:
                print(f"# avertissement : trame {numero + 1} tronquée en fin de fichier, ignorée",
                      file=sys.stderr)
                return
            numero += 1
            t = sec + frac / diviseur
            if t0 is None:
                t0 = t
            yield Trame(numero, t - t0, orig, donnees)


# ---------------------------------------------------------------------------
# 2. En-tête USBPcap
#    Source : https://desowin.org/usbpcap/captureformat.html
#    USBPCAP_BUFFER_PACKET_HEADER, structure « packée », petit-boutiste, 27 octets :
#      USHORT headerLen ; UINT64 irpId ; USBD_STATUS status ; USHORT function ;
#      UCHAR info ; USHORT bus ; USHORT device ; UCHAR endpoint ; UCHAR transfer ;
#      UINT32 dataLength
#    Pour un transfert de contrôle, un octet « stage » suit (headerLen = 28).
# ---------------------------------------------------------------------------

ENTETE_USBPCAP = struct.Struct("<HQIHBHHBBI")  # 27 octets

TRANSFERT_ISOCHRONE = 0
TRANSFERT_INTERRUPTION = 1
TRANSFERT_CONTROLE = 2
TRANSFERT_BULK = 3
TRANSFERT_IRP_INFO = 0xFE  # URB sans transfert de données (reset de pipe, abort…)
NOMS_TRANSFERT = {0: "ISOCH", 1: "INT", 2: "CTRL", 3: "BULK", 0xFE: "IRP", 0xFF: "?"}

# Étapes d'un transfert de contrôle vues par USBPcap (même source).
ETAPE_SETUP, ETAPE_DATA, ETAPE_STATUS, ETAPE_COMPLETE = 0, 1, 2, 3
NOMS_ETAPE = {0: "SETUP", 1: "DATA", 2: "STATUS", 3: "COMPLETE"}

# Codes URB_FUNCTION_* (WDK, usb.h). Seuls ceux qu'on s'attend à croiser.
NOMS_FONCTION_URB = {
    0x0000: "SELECT_CONFIGURATION",
    0x0001: "SELECT_INTERFACE",
    0x0002: "ABORT_PIPE",
    0x0008: "CONTROL_TRANSFER",
    0x0009: "BULK_OR_INTERRUPT_TRANSFER",
    0x000A: "ISOCH_TRANSFER",
    0x000B: "GET_DESCRIPTOR_FROM_DEVICE",
    0x0017: "VENDOR_DEVICE",
    0x001A: "CLASS_DEVICE",
    0x001B: "CLASS_INTERFACE",
    0x001E: "SYNC_RESET_PIPE_AND_CLEAR_STALL",
    0x0028: "GET_DESCRIPTOR_FROM_INTERFACE",
    0x0030: "SYNC_RESET_PIPE",
    0x0031: "SYNC_CLEAR_STALL",
    0x0032: "CONTROL_TRANSFER_EX",
}

# Codes USBD_STATUS_* (WDK, usb.h). 0 = succès.
NOMS_STATUT_USBD = {
    0x00000000: "SUCCESS",
    0xC0000004: "STALL_PID",
    0xC0000005: "DEV_NOT_RESPONDING",
    0xC0010000: "CANCELED",
}


@dataclass
class PaquetUsb:
    trame: Trame
    irp_id: int
    statut: int
    fonction: int
    retour: bool        # bit 0 de info : 1 = remontée PDO→FDO (complétion de l'IRP)
    bus: int
    adresse: int
    endpoint: int       # bit 7 = 1 : sens IN (vers l'hôte)
    transfert: int
    longueur_donnees: int  # longueur réelle annoncée par USBPcap
    etape: int | None
    donnees: bytes         # octets réellement capturés après l'en-tête

    @property
    def tronque(self):
        return len(self.donnees) < self.longueur_donnees


def decoder_usbpcap(trame):
    d = trame.donnees
    if len(d) < ENTETE_USBPCAP.size:
        return None
    (lg_entete, irp_id, statut, fonction, info, bus, adresse,
     endpoint, transfert, lg_donnees) = ENTETE_USBPCAP.unpack_from(d)
    etape = d[27] if transfert == TRANSFERT_CONTROLE and lg_entete >= 28 else None
    return PaquetUsb(trame, irp_id, statut, fonction, bool(info & 1), bus, adresse,
                     endpoint, transfert, lg_donnees, etape, d[lg_entete:])


def nom_statut(statut):
    return NOMS_STATUT_USBD.get(statut, f"0x{statut:08X}")


# ---------------------------------------------------------------------------
# 3. Transferts de contrôle et descripteurs
#    Paquet SETUP de 8 octets : USB 2.0 §9.3, table 9-2.
#    Requêtes standard : table 9-4. Types de descripteur : table 9-5.
#    Requêtes de classe Mass Storage : BOT §3.1 (reset) et §3.2 (Get Max LUN).
# ---------------------------------------------------------------------------

REQUETES_STANDARD = {
    0: "GET_STATUS", 1: "CLEAR_FEATURE", 3: "SET_FEATURE", 5: "SET_ADDRESS",
    6: "GET_DESCRIPTOR", 7: "SET_DESCRIPTOR", 8: "GET_CONFIGURATION",
    9: "SET_CONFIGURATION", 10: "GET_INTERFACE", 11: "SET_INTERFACE", 12: "SYNCH_FRAME",
}
REQUETES_CLASSE_BOT = {0xFF: "BULK_ONLY_RESET", 0xFE: "GET_MAX_LUN"}
TYPES_DESCRIPTEUR = {
    1: "DEVICE", 2: "CONFIGURATION", 3: "STRING", 4: "INTERFACE", 5: "ENDPOINT",
    6: "DEVICE_QUALIFIER", 7: "OTHER_SPEED_CONFIGURATION", 8: "INTERFACE_POWER", 0x0F: "BOS",
}
TYPES_ENDPOINT = {0: "contrôle", 1: "isochrone", 2: "bulk", 3: "interruption"}


def decrire_setup(s):
    """Texte lisible d'un paquet SETUP (8 octets)."""
    bm, req, valeur, index, longueur = struct.unpack("<BBHHH", s)
    sens = "IN" if bm & 0x80 else "OUT"
    genre = (bm >> 5) & 3        # 0 standard, 1 classe, 2 vendeur
    if genre == 0:
        nom = REQUETES_STANDARD.get(req, f"STANDARD_0x{req:02X}")
        if req == 6:
            type_desc = TYPES_DESCRIPTEUR.get(valeur >> 8, f"0x{valeur >> 8:02X}")
            return f"{nom} {type_desc} index={valeur & 0xFF} langue=0x{index:04X} wLength={longueur} ({sens})"
        if req == 9:
            return f"{nom} valeur={valeur}"
        if req == 11:
            return f"{nom} interface={index} alternatif={valeur}"
    elif genre == 1:
        nom = REQUETES_CLASSE_BOT.get(req, f"CLASSE_0x{req:02X}")
    else:
        nom = f"VENDEUR_0x{req:02X}" if genre == 2 else f"RÉSERVÉ_0x{req:02X}"
    return f"{nom} wValue=0x{valeur:04X} wIndex=0x{index:04X} wLength={longueur} ({sens})"


def decrire_descripteurs(octets, index_chaine=None):
    """Découpe une suite de descripteurs (bLength, bDescriptorType, …) et décrit
    chacun sur une ligne. Une réponse CONFIGURATION contient la configuration,
    puis ses interfaces et endpoints, à la suite (USB 2.0 §9.4.3).
    index_chaine : index demandé dans le SETUP, car le descripteur STRING d'index 0
    n'est pas un texte mais la liste des langues gérées (§9.6.7)."""
    lignes = []
    i = 0
    while i + 2 <= len(octets):
        lg, typ = octets[i], octets[i + 1]
        if lg < 2:
            lignes.append(f"bLength={lg} invalide à l'octet {i}, arrêt")
            break
        d = octets[i:i + lg]
        if len(d) < lg:
            lignes.append(f"{TYPES_DESCRIPTEUR.get(typ, hex(typ))} incomplet ({len(d)}/{lg} o)")
            break
        if typ == 1 and lg >= 18:  # table 9-8
            (_, _, bcd_usb, classe, sous_classe, proto, max0, vid, pid, bcd_dev,
             i_fab, i_prod, i_serie, n_conf) = struct.unpack("<BBHBBBBHHHBBBB", d[:18])
            lignes.append(
                f"DEVICE USB {bcd_usb >> 8:x}.{bcd_usb & 0xFF:02x} classe={classe:02X}/{sous_classe:02X}/{proto:02X} "
                f"bMaxPacketSize0={max0} VID=0x{vid:04X} PID=0x{pid:04X} bcdDevice=0x{bcd_dev:04X} "
                f"iManufacturer={i_fab} iProduct={i_prod} iSerial={i_serie} configurations={n_conf}")
        elif typ == 2 and lg >= 9:  # table 9-10
            _, _, total, n_itf, valeur, i_conf, attributs, max_power = struct.unpack("<BBHBBBBB", d[:9])
            lignes.append(
                f"CONFIGURATION wTotalLength={total} interfaces={n_itf} bConfigurationValue={valeur} "
                f"attributs=0x{attributs:02X} courant max={max_power * 2} mA")
        elif typ == 4 and lg >= 9:  # table 9-12
            _, _, num, alt, n_ep, classe, sous_classe, proto, _ = struct.unpack("<BBBBBBBBB", d[:9])
            lignes.append(
                f"INTERFACE n°{num} alt={alt} endpoints={n_ep} classe={classe:02X}/{sous_classe:02X}/{proto:02X}")
        elif typ == 5 and lg >= 7:  # table 9-13
            _, _, adr, attributs, max_paquet, intervalle = struct.unpack("<BBBBHB", d[:7])
            sens = "IN" if adr & 0x80 else "OUT"
            lignes.append(
                f"ENDPOINT 0x{adr:02X} ({sens}, {TYPES_ENDPOINT[attributs & 3]}) "
                f"wMaxPacketSize={max_paquet} bInterval={intervalle}")
        elif typ == 3 and index_chaine == 0:  # §9.6.7 : liste de LANGID sur 16 bits
            langues = struct.unpack(f"<{(lg - 2) // 2}H", d[2:2 + (lg - 2) // 2 * 2])
            lignes.append("STRING 0 : langues " + ", ".join(f"0x{l:04X}" for l in langues))
        elif typ == 3:  # §9.6.7 : texte UTF-16LE
            texte = d[2:].decode("utf-16-le", errors="replace")
            lignes.append(f"STRING « {texte} » ({d[2:].hex(' ')})")
        else:
            lignes.append(f"{TYPES_DESCRIPTEUR.get(typ, f'type 0x{typ:02X}')} {lg} o : {d.hex(' ')}")
        i += lg
    return lignes


# ---------------------------------------------------------------------------
# 4. Transport Bulk-Only et SCSI
#    CBW : BOT §5.1, 31 octets, signature 'USBC' (0x43425355).
#    CSW : BOT §5.2, 13 octets, signature 'USBS' (0x53425355).
#    Un CBW n'est valide que s'il fait 31 octets et porte la signature (BOT §6.2.1) ;
#    un CSW, s'il fait 13 octets, porte la signature et le tag du CBW (BOT §6.3.1).
# ---------------------------------------------------------------------------

CBW = struct.Struct("<IIIBBB16s")  # signature, tag, longueur, flags, lun, lg CDB, CDB
CSW = struct.Struct("<IIIB")       # signature, tag, résidu, statut
SIGNATURE_CBW = 0x43425355
SIGNATURE_CSW = 0x53425355
STATUTS_CSW = {0: "réussite", 1: "échec", 2: "erreur de phase"}  # BOT §5.2, table 5.3

# Noms des opcodes SCSI rencontrés. Sources : SPC-4 (commandes communes), SBC-3
# (périphériques bloc), spécification UFI 1.0 pour READ FORMAT CAPACITIES.
OPCODES_SCSI = {
    0x00: "TEST UNIT READY", 0x03: "REQUEST SENSE", 0x12: "INQUIRY",
    0x1A: "MODE SENSE(6)", 0x1B: "START STOP UNIT", 0x1E: "PREVENT ALLOW MEDIUM REMOVAL",
    0x23: "READ FORMAT CAPACITIES", 0x25: "READ CAPACITY(10)", 0x28: "READ(10)",
    0x5A: "MODE SENSE(10)", 0x9E: "SERVICE ACTION IN(16)",
}
# Opcodes qui modifient le support ou le firmware : interdits par CLAUDE.md.
# Les signaler en clair si le logiciel Brother les emploie.
OPCODES_DANGEREUX = {
    0x04: "FORMAT UNIT", 0x0A: "WRITE(6)", 0x2A: "WRITE(10)", 0x2E: "WRITE AND VERIFY(10)",
    0x3B: "WRITE BUFFER", 0xAA: "WRITE(12)", 0x8A: "WRITE(16)",
}


# Clés de sense (SPC-4, table « Sense key descriptions »).
CLES_SENSE = {
    0x0: "NO SENSE", 0x1: "RECOVERED ERROR", 0x2: "NOT READY", 0x3: "MEDIUM ERROR",
    0x4: "HARDWARE ERROR", 0x5: "ILLEGAL REQUEST", 0x6: "UNIT ATTENTION", 0x7: "DATA PROTECT",
    0x8: "BLANK CHECK", 0x9: "VENDOR SPECIFIC", 0xB: "ABORTED COMMAND", 0xE: "MISCOMPARE",
}


def decrire_reponse_scsi(cdb, donnees):
    """Décode les réponses des commandes standard qu'on sait lire ; liste vide sinon."""
    if not cdb or not donnees:
        return []
    op = cdb[0]
    if op == 0x03 and len(donnees) >= 14 and donnees[0] & 0x7F in (0x70, 0x71):
        # Sense au format fixe (SPC-4, « Fixed format sense data ») : clé octet 2,
        # ASC octet 12, ASCQ octet 13.
        cle = donnees[2] & 0x0F
        return [f"sense : clé 0x{cle:X} ({CLES_SENSE.get(cle, '?')}) "
                f"ASC/ASCQ = 0x{donnees[12]:02X}/0x{donnees[13]:02X}"]
    if op == 0x12 and len(cdb) > 1 and not cdb[1] & 1 and len(donnees) >= 36:
        # Données INQUIRY standard (SPC-4, « Standard INQUIRY data ») : type de
        # périphérique sur 5 bits, puis vendeur 8..15, produit 16..31, révision 32..35.
        texte = lambda a, b: donnees[a:b].decode("ascii", errors="replace").strip()
        return [f"INQUIRY : type 0x{donnees[0] & 0x1F:02X}, amovible={donnees[1] >> 7}, "
                f"vendeur « {texte(8, 16)} », produit « {texte(16, 32)} », révision « {texte(32, 36)} »"]
    if op == 0x25 and len(donnees) >= 8:
        # READ CAPACITY(10) (SBC-3) : dernier LBA et taille de bloc, gros-boutistes.
        dernier, bloc = struct.unpack(">II", donnees[:8])
        return [f"capacité : {dernier + 1} blocs de {bloc} o = {(dernier + 1) * bloc} o"]
    return []


def nom_opcode(op):
    if op in OPCODES_DANGEREUX:
        return f"{OPCODES_DANGEREUX[op]} !! ÉCRITURE"
    if op in OPCODES_SCSI:
        return OPCODES_SCSI[op]
    if op >= 0xC0:  # groupes 6 et 7 des codes d'opération : réservés aux fabricants (SPC-4)
        return f"VENDEUR 0x{op:02X}"
    return f"opcode 0x{op:02X}"


# ---------------------------------------------------------------------------
# 5. Protocole vendeur du DS-720D (étape 3a ; détail et trames dans docs/protocole.md)
#    Il n'existe pas de spécification publique de ce protocole : tout ce qui suit
#    est lu dans les captures du pilote Brother. Ce qui n'est que déduit est dit
#    tel quel dans les commentaires et dans docs/protocole.md.
#
#    0xC3 et 0xC5 sont du groupe 6 des codes d'opération, réservé aux fabricants
#    (SCSI-2 §7.2.1). Leur CDB de 16 octets a la même forme dans toutes les captures :
#      octets 0-1    opcode, puis 0x07 (constant, sens inconnu)
#      octets 2-5    adresse dans la mémoire du scanner, gros-boutiste (0 pour 0xC5)
#      octets 6-9    longueur des données, gros-boutiste, égale à celle du CBW
#      octets 10-12  sélecteur (0 pour 0xC3)
#      octets 13-15  0
#    0xC5 est un tunnel : le sélecteur 02 03 00 y dépose une commande du jeu
#    « Scanner devices » de SCSI-2 (chapitre 15), les autres sélecteurs lisent la
#    réponse ou l'état. 0xC3 lit un bloc d'image à l'adresse que l'état annonce.
# ---------------------------------------------------------------------------

OP_TUNNEL, OP_LECTURE_TAMPON = 0xC5, 0xC3

# Troisième octet des sélecteurs 02 01 k et 02 02 k : quelle réponse on lit.
# Déduit de l'ordre des échanges (docs/protocole.md) : k=0 suit une commande qui
# rend des données, k=1 suit toutes les commandes, k=2 suit READ image. k=3 et
# k=4 se lisent sans commande déposée et rendent 04 f9 et 60 e2, l'idVendor et
# l'idProduct du descripteur DEVICE (vérifié dans 1b, trame 20896).
GENRES_REPONSE = {0: "données", 1: "statut", 2: "bloc d'image",
                  3: "identifiant fabricant", 4: "identifiant produit"}


def decrire_selecteur(sel):
    """Nom d'un sélecteur de 0xC5 (octets 10 à 12 du CDB)."""
    a, b, k = sel
    if (a, b, k) == (0xFF, 0x02, 0):
        return "signature"
    if a == 0xFF and 0x03 <= b <= 0x06 and k == 0:
        return "sondage d'état"
    if (a, b, k) == (0x02, 0x03, 0):
        return "dépôt d'une commande"
    if a == 0x02 and b in (0x01, 0x02) and k in GENRES_REPONSE:
        quoi = "en-tête de réponse" if b == 0x01 else "réponse"
        return f"{quoi}, {GENRES_REPONSE[k]}"
    return "inconnu"


def decrire_cdb_vendeur(cdb):
    """Ligne de détail sous le CBW d'une commande 0xC3 ou 0xC5. Les écarts à la
    forme connue sont signalés par « !! » : un CDB qui en sort est du jamais vu."""
    if len(cdb) != 16:
        return [f"!! CDB vendeur de {len(cdb)} o (attendu 16)"]
    op = cdb[0]
    adresse, longueur = struct.unpack(">II", cdb[2:10])
    anomalies = []
    if cdb[1] != 0x07:
        anomalies.append(f"octet 1 = 0x{cdb[1]:02X} (attendu 07)")
    if any(cdb[13:16]):
        anomalies.append("octets 13-15 non nuls")
    if op == OP_TUNNEL:
        if adresse:
            anomalies.append(f"adresse 0x{adresse:08X} (attendue 0)")
        sel = cdb[10:13]
        texte = f"tunnel 0xC5, sélecteur {sel.hex(' ')} : {decrire_selecteur(sel)}"
    else:
        if any(cdb[10:13]):
            anomalies.append("octets 10-12 non nuls")
        texte = f"lecture 0xC3 à l'adresse 0x{adresse:08X}"
    return [texte + f", {longueur} o" + "".join(f"  !! {a}" for a in anomalies)]


# Commandes du jeu « Scanner devices », SCSI-2 table 277 (§15.2), avec la
# sous-clause qui les définit. 0x2A y est SEND, pas WRITE(10) : dans le tunnel,
# il envoie des paramètres au scanner, il n'écrit pas de secteur.
COMMANDES_SCANNER = {
    0x00: ("TEST UNIT READY", "§8.2.16"), 0x03: ("REQUEST SENSE", "§8.2.14"),
    0x12: ("INQUIRY", "§8.2.5"), 0x16: ("RESERVE UNIT", "§10.2.10"),
    0x17: ("RELEASE UNIT", "§10.2.9"), 0x1B: ("SCAN", "§15.2.5"),
    0x24: ("SET WINDOW", "§15.2.7"), 0x25: ("GET WINDOW", "§15.2.2"),
    0x28: ("READ", "§15.2.4"), 0x2A: ("SEND", "§15.2.6"),
    0x31: ("OBJECT POSITION", "§15.2.3"), 0x34: ("GET DATA BUFFER STATUS", "§15.2.1"),
}
# Ce qui, emballé, toucherait au firmware ou à un support : WRITE BUFFER (SCSI-2
# §8.2.17) télécharge du microcode ; les autres n'ont rien à faire chez un scanner.
COMMANDES_SCANNER_DANGEREUSES = {
    0x04: "FORMAT UNIT", 0x0A: "WRITE(6)", 0x2E: "WRITE AND VERIFY(10)",
    0x3B: "WRITE BUFFER", 0x8A: "WRITE(16)", 0xAA: "WRITE(12)",
}
# Codes de type de données de READ et SEND, SCSI-2 table 289 (§15.2.4).
TYPES_DONNEES = {0x00: "image", 0x01: "vendeur", 0x02: "masque de demi-teinte",
                 0x03: "fonction gamma"}
# Composition d'image du descripteur de fenêtre, SCSI-2 table 283 (§15.2.7).
COMPOSITIONS = {0: "noir et blanc 1 bit", 1: "noir et blanc tramé", 2: "gris multiniveau",
                3: "RVB 1 bit", 4: "RVB tramé", 5: "RVB multiniveau"}
# Type de bourrage de fin de ligne, SCSI-2 table 284.
BOURRAGES = {0: "aucun", 1: "zéros jusqu'à l'octet", 2: "uns jusqu'à l'octet",
             3: "tronqué à l'octet"}
# Unité des coordonnées de fenêtre : 1/1200 de pouce par défaut (SCSI-2 §15.3.3.1).
UNITES_PAR_POUCE = 1200

# Zone de dépôt : le CDB emballé occupe les 10 premiers octets (un CDB de 6 o,
# groupe 0, y est complété par des zéros), les données éventuelles suivent.
# Vérifié : 12 = 10 + 2 pour SEND 0x95, 89 = 10 + 0x4F pour SET WINDOW.
LG_ZONE_CDB = 10


def nom_type_donnees(code):
    if code in TYPES_DONNEES:
        return TYPES_DONNEES[code]
    return "vendeur" if code >= 0x80 else "réservé"


def contient_serie_depot(depot):
    """SEND type 0x85 : Capture Tool y envoie la date et le numéro de série du
    scanner (1e-gris-300-recto). Ses données ne s'affichent pas sans --serie."""
    # Même seuil que src/trace.c : au-delà de la zone de CDB, il y a des données.
    return len(depot) > LG_ZONE_CDB and depot[0] == 0x2A and depot[2] == 0x85


def decrire_fenetre(params):
    """Paramètres de SET WINDOW (SCSI-2 §15.2.7) : en-tête de 8 octets (table 293,
    longueur du descripteur en octets 6-7) puis descripteur de fenêtre (table 282)."""
    if len(params) < 8:
        return [f"!! paramètres de SET WINDOW trop courts ({len(params)} o)"]
    lg_desc = struct.unpack(">H", params[6:8])[0]
    d = params[8:8 + lg_desc]
    lignes = []
    if len(d) < 40 or len(d) != lg_desc:
        return [f"!! descripteur de fenêtre de {len(d)} o (annoncé {lg_desc})"]
    ident, auto = d[0], d[1] & 1
    res_x, res_y = struct.unpack(">HH", d[2:6])
    x, y, largeur, longueur = struct.unpack(">IIII", d[6:22])
    pouces = lambda v: f"{v / UNITES_PAR_POUCE:.3f}"
    lignes.append(f"fenêtre {ident}, auto={auto} : {res_x} × {res_y} ppp, origine ({x}, {y}), "
                  f"{largeur} × {longueur} unités ({pouces(largeur)} × {pouces(longueur)} po à 1/1200 po)")
    compo = COMPOSITIONS.get(d[25], "réservé")
    lignes.append(f"luminosité 0x{d[22]:02X}, seuil 0x{d[23]:02X}, contraste 0x{d[24]:02X}, "
                  f"composition {d[25]:02X} ({compo}), {d[26]} bits par pixel")
    demi_teinte, ordre_bits = struct.unpack(">H", d[27:29])[0], struct.unpack(">H", d[30:32])[0]
    lignes.append(f"demi-teinte 0x{demi_teinte:04X}, RIF {d[29] >> 7}, bourrage {d[29] & 7} "
                  f"({BOURRAGES.get(d[29] & 7, 'réservé')}), ordre des bits 0x{ordre_bits:04X}, "
                  f"compression {d[32]:02X}/{d[33]:02X}")
    vendeur = d[40:]
    lignes.append(f"octets vendeur ({len(vendeur)}) : {vendeur.hex(' ')}")
    return lignes


def decrire_depot(depot, montrer_serie=False):
    """Lignes de détail sous le DATA-OUT d'un dépôt (sélecteur 02 03 00) : la
    commande SCSI-2 emballée, puis ses paramètres quand on sait les lire."""
    if len(depot) < LG_ZONE_CDB:
        return [f"!! dépôt de {len(depot)} o (attendu au moins {LG_ZONE_CDB})"]
    op = depot[0]
    lg_cdb = 6 if op < 0x20 else 10      # groupe 0 : 6 o ; groupe 1 : 10 o (SCSI-2 §7.2.1)
    cdb, donnees = depot[:lg_cdb], depot[LG_ZONE_CDB:]
    if op in COMMANDES_SCANNER_DANGEREUSES:
        nom = f"{COMMANDES_SCANNER_DANGEREUSES[op]} !! ÉCRITURE"
    elif op in COMMANDES_SCANNER:
        nom = "{} (SCSI-2 {})".format(*COMMANDES_SCANNER[op])
    else:
        nom = f"opcode 0x{op:02X} (absent de la table 277 des scanners)"
    texte = f"commande emballée : {nom}, CDB[{lg_cdb}]={cdb.hex(' ')}"
    if any(depot[lg_cdb:LG_ZONE_CDB]):
        texte += "  !! zone de CDB non nulle après le CDB"
    detail = []
    if op in (0x28, 0x2A):
        # READ et SEND, SCSI-2 tables 288 et 291 : type octet 2, qualificatif 4-5,
        # longueur 6-8, gros-boutistes.
        qualif = struct.unpack(">H", cdb[4:6])[0]
        lg = int.from_bytes(cdb[6:9], "big")
        texte += (f", type 0x{cdb[2]:02X} ({nom_type_donnees(cdb[2])}), "
                  f"qualificatif 0x{qualif:04X}, {lg} o")
        if op == 0x2A and lg != len(donnees):
            texte += f"  !! {len(donnees)} o de données déposés"
        if op == 0x2A and contient_serie_depot(depot) and not montrer_serie:
            detail.append("données : (numéro de série masqué, --serie)")
        elif op == 0x2A:
            detail.append(f"données : {donnees.hex(' ')}")
    elif op == 0x24:
        lg = int.from_bytes(cdb[6:9], "big")  # SCSI-2 table 292 : longueur octets 6-8
        texte += f", {lg} o de paramètres"
        if lg != len(donnees):
            texte += f"  !! {len(donnees)} o déposés"
        detail += decrire_fenetre(donnees)
    elif op == 0x1B:
        # SCAN, SCSI-2 table 290 : octet 4 = longueur de la liste de fenêtres ;
        # octet de contrôle : bits 7-6 réservés au fabricant (SCSI-2 §7.2.7).
        texte += f", liste de fenêtres de {cdb[4]} o, contrôle 0x{cdb[5]:02X}"
    elif op < 0x20:
        texte += f", octet 4 = {cdb[4]}"  # longueur d'allocation ou de transfert du groupe 0
    if op != 0x2A and op != 0x24 and donnees:
        detail.append(f"données : {donnees.hex(' ')}")
    return [texte] + detail


# Mots de 32 bits petit-boutistes de la réponse « bloc d'image » (02 02 02, 24 o).
# Vérifié sur 2a : l'adresse (mot 5) est celle du 0xC3 suivant, et le produit des
# mots 3 et 4 est le volume que lisent les 0xC3 du bloc. Le sens de ces deux
# facteurs (octets par ligne, lignes) n'est que déduit.
ETATS_BLOC = {0: "pas prêt", 1: "prêt", 3: "fin de page"}


def decrire_reponse_vendeur(cdb, donnees):
    """Détail des réponses 0xC5 qu'on sait lire ; liste vide sinon."""
    if len(cdb) != 16 or cdb[0] != OP_TUNNEL:
        return []
    sel = tuple(cdb[10:13])
    if sel == (0xFF, 0x02, 0) and len(donnees) == 4:
        return [f"signature « {donnees.decode('ascii', errors='replace')} »"]
    if sel == (0x02, 0x02, 2) and len(donnees) == 24:
        etat, _, _, a, b, adresse = struct.unpack("<6I", donnees)
        return [f"bloc d'image : état {etat} ({ETATS_BLOC.get(etat, '?')}), "
                f"{a} × {b} = {a * b} o, adresse 0x{adresse:08X}"]
    if sel in ((0x02, 0x02, 3), (0x02, 0x02, 4)) and len(donnees) == 2:
        return [f"identifiant 0x{struct.unpack('>H', donnees)[0]:04X}"]
    if sel == (0x02, 0x02, 1) and len(donnees) == 4:
        return [f"statut de la commande : 0x{struct.unpack('<I', donnees)[0]:08X}"]
    return []


# ---------------------------------------------------------------------------
# Production des lignes de trace
# ---------------------------------------------------------------------------

# Préfixe des lignes de détail (décodage d'un descripteur, d'une réponse SCSI…) :
# elles s'alignent sous la colonne « détail » et commencent par « | ».
SUITE = " " * 36 + "| "


def hexa(octets, maxi):
    if maxi < 0 or len(octets) <= maxi:
        return octets.hex(" ")
    return octets[:maxi].hex(" ") + " …"


class Decodeur:
    """Suit l'état d'un appareil (contrôles en vol, commande BOT en cours) et
    transforme les paquets USBPcap en lignes du format de trace commun."""

    def __init__(self, octets_max, masques, montrer_serie=False, recoller=False):
        self.octets_max = octets_max
        self.masques = masques
        self.montrer_serie = montrer_serie
        # Étape 6g : quand la VM passe par VMware, l'hôte découpe une phase de
        # données de 64 Kio en plusieurs URB (36 864 + 28 672 o, capture
        # 6g-recto) ; USBPcap, sur l'hôte, voit les morceaux. Avec recoller,
        # les données entrantes d'une même commande sont rassemblées en une
        # seule ligne DATA-IN, comme les voit le pilote de la VM (un seul URB),
        # au numéro de trame du premier morceau. Sans effet sur une capture où
        # chaque phase tient en un URB (toutes celles de Medabot).
        self.recoller = recoller
        self.attente = {}      # adresse -> morceaux [(paquet, octets)] de la phase de données en cours
        self.i_serie = {}      # adresse -> index du descripteur STRING du numéro de série
        self.setups = {}       # irp_id -> paquet SETUP (pour décoder la réponse)
        self.cbw = {}          # adresse -> (tag, opcode, CDB) de la commande en cours
        self.stats = Counter()
        self.volume_in = Counter()  # opcode -> octets DATA-IN reçus
        self.tronques = 0

    def ligne(self, p, evenement, detail):
        return f"{p.trame.numero:<8} {p.trame.temps:12.6f}  {p.adresse:>3}  {evenement:<10} {detail}"

    def masque(self, p):
        cour = self.cbw.get(p.adresse)
        return cour is not None and cour[1] in self.masques

    def traiter(self, p):
        """Renvoie la liste des lignes à afficher pour ce paquet."""
        if p.tronque:
            self.tronques += 1
        t = p.transfert
        # Option recoller : tout paquet de cet appareil qui n'est pas la suite
        # de la phase de données en cours (soumission IN, morceau IN sans
        # erreur) la termine ; ses morceaux s'écrivent alors avant lui, dans
        # l'ordre des trames. Depuis 6i (relecture) : une ligne ERREUR passait
        # jusque-là avant les données recollées qui la précédaient.
        sortie = [] if self.suite_de_donnees(p) else self.vider(p.adresse)
        if p.statut != 0 and p.retour:
            self.stats["erreurs"] += 1
            sortie.append(self.ligne(p, "ERREUR",
                                     f"ep=0x{p.endpoint:02X} {NOMS_TRANSFERT.get(t, t)} "
                                     f"USBD_STATUS_{nom_statut(p.statut)}"))
        if t == TRANSFERT_CONTROLE:
            return sortie + self.controle(p)
        if t == TRANSFERT_BULK:
            return sortie + self.bulk(p)
        if t == TRANSFERT_IRP_INFO and not p.retour:
            nom = NOMS_FONCTION_URB.get(p.fonction, f"0x{p.fonction:04X}")
            return sortie + [self.ligne(p, "URB", f"{nom} ep=0x{p.endpoint:02X}")]
        if t == TRANSFERT_INTERRUPTION and p.retour and p.donnees:
            return sortie + [self.ligne(p, "INT-IN", f"ep=0x{p.endpoint:02X} {len(p.donnees)} o  "
                                                     f"{hexa(p.donnees, self.octets_max)}")]
        return sortie

    def controle(self, p):
        if p.etape == ETAPE_SETUP and not p.retour and len(p.donnees) >= 8:
            setup = p.donnees[:8]
            self.setups[p.irp_id] = setup
            self.stats["setup"] += 1
            return [self.ligne(p, "SETUP", f"{setup.hex(' ')}  {decrire_setup(setup)}")]
        if p.etape == ETAPE_DATA and not p.retour and p.donnees:
            return [self.ligne(p, "CTRL-OUT", f"{len(p.donnees)} o  {hexa(p.donnees, self.octets_max)}")]
        if p.retour and p.donnees and p.etape in (ETAPE_DATA, ETAPE_COMPLETE):
            setup = self.setups.pop(p.irp_id, None)
            get_descripteur = setup and setup[0] & 0x80 and setup[0] & 0x60 == 0 and setup[1] == 6
            if get_descripteur and setup[3] == 1 and len(p.donnees) >= 18:
                self.i_serie[p.adresse] = p.donnees[16]  # iSerialNumber (table 9-8)
            if (get_descripteur and setup[3] == 3 and setup[2] != 0
                    and setup[2] == self.i_serie.get(p.adresse) and not self.montrer_serie):
                # Le numéro de série identifie l'appareil de David : masqué par défaut,
                # pour qu'il ne finisse pas dans le dépôt au détour d'une trace copiée.
                return [self.ligne(p, "CTRL-IN", f"{len(p.donnees)} o  (numéro de série masqué, --serie)")]
            lignes = [self.ligne(p, "CTRL-IN", f"{len(p.donnees)} o  {hexa(p.donnees, self.octets_max)}")]
            if get_descripteur:
                lignes += [SUITE + l for l in decrire_descripteurs(p.donnees, index_chaine=setup[2])]
            elif setup and setup[1] == 0xFE and setup[0] & 0x60 == 0x20:
                lignes.append(SUITE + f"plus haut LUN = {p.donnees[0]}")
            return lignes
        if p.retour:
            self.setups.pop(p.irp_id, None)
        return []

    def bulk(self, p):
        d = p.donnees
        entrant = bool(p.endpoint & 0x80)
        if not entrant and not p.retour:
            # Soumission OUT : les octets partent vers le scanner.
            if len(d) == CBW.size and d[:4] == b"USBC":
                # Morceaux en attente d'une commande sans CSW : à écrire avant.
                avant = self.vider(p.adresse)
                _, tag, lg, flags, lun, lg_cdb, cdb = CBW.unpack(d)
                cdb = cdb[:lg_cdb]
                op = cdb[0] if cdb else -1
                self.cbw[p.adresse] = (tag, op, cdb)
                sens = "IN" if flags & 0x80 else "OUT"
                self.stats[("CBW", op, lg, sens)] += 1
                if op in self.masques:
                    return avant
                lignes = [self.ligne(p, "CBW", f"tag=0x{tag:08X} lun={lun} {sens} {lg} o  "
                                               f"CDB[{lg_cdb}]={cdb.hex(' ')}  {nom_opcode(op)}")]
                if op in (OP_TUNNEL, OP_LECTURE_TAMPON):
                    lignes += [SUITE + l for l in decrire_cdb_vendeur(cdb)]
                return avant + lignes
            if d:
                self.stats["data-out"] += 1
                cour = self.cbw.get(p.adresse)
                depot = (cour is not None and cour[1] == OP_TUNNEL and len(cour[2]) == 16
                         and cour[2][10:13] == b"\x02\x03\x00")
                if depot:
                    self.stats[("DEPOT", d[0], len(d))] += 1
                if self.masque(p):
                    return []
                if depot and contient_serie_depot(d) and not self.montrer_serie:
                    lignes = [self.ligne(p, "DATA-OUT", f"{len(d)} o  {d[:LG_ZONE_CDB].hex(' ')} "
                                                        f"+ {len(d) - LG_ZONE_CDB} o "
                                                        f"(numéro de série masqué, --serie)")]
                else:
                    lignes = [self.ligne(p, "DATA-OUT", f"{len(d)} o  {hexa(d, self.octets_max)}")]
                if depot:
                    lignes += [SUITE + l for l in decrire_depot(d, self.montrer_serie)]
                return lignes
            return []
        if entrant and p.retour and (d or p.longueur_donnees):
            # Complétion IN : les octets arrivent du scanner.
            cour = self.cbw.get(p.adresse)
            if len(d) == CSW.size and d[:4] == b"USBS":
                avant = self.vider(p.adresse)
                _, tag, residu, statut = CSW.unpack(d)
                attendu = cour[0] if cour else None
                masque = self.masque(p)
                self.cbw.pop(p.adresse, None)
                self.stats[("CSW", statut)] += 1
                if masque:
                    return avant
                alerte = "" if tag == attendu else f"  !! tag inattendu (CBW 0x{attendu or 0:08X})"
                return avant + [self.ligne(p, "CSW", f"tag=0x{tag:08X} statut={statut} "
                                                     f"({STATUTS_CSW.get(statut, '?')}) résidu={residu}{alerte}")]
            if self.recoller:
                self.attente.setdefault(p.adresse, []).append((p, d))
                return []
            return self.donnees_in(p, d, p.longueur_donnees, p.tronque)
        return []

    def suite_de_donnees(self, p):
        """Vrai si ce paquet prolonge la phase de données entrante en cours :
        soumission d'une lecture bulk, ou morceau reçu sans erreur qui n'est pas
        un CSW."""
        if p.transfert != TRANSFERT_BULK or not p.endpoint & 0x80 or p.statut != 0:
            return False
        if not p.retour:
            return True
        return not (len(p.donnees) == CSW.size and p.donnees[:4] == b"USBS")

    def vider(self, adresse):
        """Lignes de la phase de données entrante recollée en attente pour cette
        adresse (option recoller), ou rien."""
        morceaux = self.attente.pop(adresse, None)
        if not morceaux:
            return []
        premier = morceaux[0][0]
        return self.donnees_in(premier, b"".join(d for _, d in morceaux),
                               sum(p.longueur_donnees for p, _ in morceaux), any(p.tronque for p, _ in morceaux))

    def donnees_in(self, p, d, longueur, tronque_capture):
        """Ligne DATA-IN (et son décodage) pour longueur octets reçus, dont d capturés."""
        cour = self.cbw.get(p.adresse)
        if cour:
            self.volume_in[cour[1]] += longueur
        self.stats["data-in"] += 1
        if self.masque(p):
            return []
        tronque = f" (capturés {len(d)})" if tronque_capture else ""
        demande = int.from_bytes(cour[2][6:10], "big") if cour and len(cour[2]) == 16 else 0
        if (cour and cour[1] == OP_TUNNEL and (longueur in (128, 165) or demande in (128, 165))
                and not self.montrer_serie):
            # Réponses 0xC5 de 128 et 165 o, reçues ou demandées : INQUIRY emballé
            # (12 … a5) et READ type 0x69 de 128 o, porteurs du numéro de série
            # (1b, 1e-gris-300-recto). Même règle que contient_serie() dans src/trace.c.
            return [self.ligne(p, "DATA-IN", f"{longueur} o{tronque}  "
                                             f"(numéro de série masqué, --serie)")]
        lignes = [self.ligne(p, "DATA-IN", f"{longueur} o{tronque}  {hexa(d, self.octets_max)}")]
        if cour:
            lignes += [SUITE + l for l in decrire_reponse_scsi(cour[2], d)]
            lignes += [SUITE + l for l in decrire_reponse_vendeur(cour[2], d)]
        return lignes


def decrire_brut(p):
    etape = f" étape={NOMS_ETAPE.get(p.etape, p.etape)}" if p.etape is not None else ""
    return (f"{p.trame.numero:<8} {p.trame.temps:12.6f}  irp=0x{p.irp_id:016X} "
            f"statut={nom_statut(p.statut)} fonction={NOMS_FONCTION_URB.get(p.fonction, hex(p.fonction))} "
            f"{'remontée' if p.retour else 'descente'} bus={p.bus} adr={p.adresse} ep=0x{p.endpoint:02X} "
            f"{NOMS_TRANSFERT.get(p.transfert, p.transfert)}{etape} lg={p.longueur_donnees}"
            f"{' TRONQUÉ' if p.tronque else ''}")


# ---------------------------------------------------------------------------
# Choix de l'appareil
# ---------------------------------------------------------------------------

VID_BROTHER, PID_DS720D = 0x04F9, 0x60E2


def trouver_scanner(chemin):
    """Cherche les adresses dont le descripteur DEVICE annonce 04F9:60E2. Si la
    capture ne contient pas d'énumération, renvoie le nombre de CBW par adresse
    pour que l'utilisateur choisisse avec --adresse."""
    adresses = set()
    cbw_par_adresse = Counter()
    for trame in lire_pcap(chemin):
        p = decoder_usbpcap(trame)
        if p is None:
            continue
        d = p.donnees
        if (p.transfert == TRANSFERT_CONTROLE and p.retour and len(d) >= 18
                and d[0] == 18 and d[1] == 1):
            vid, pid = struct.unpack_from("<HH", d, 8)
            if (vid, pid) == (VID_BROTHER, PID_DS720D):
                adresses.add(p.adresse)
        if p.transfert == TRANSFERT_BULK and not p.retour and len(d) == 31 and d[:4] == b"USBC":
            cbw_par_adresse[p.adresse] += 1
    return adresses, cbw_par_adresse


# ---------------------------------------------------------------------------
# Programme principal
# ---------------------------------------------------------------------------

def entier(texte):
    return int(texte, 0)


def main():
    ap = argparse.ArgumentParser(description="Analyseur de captures USBPcap pour le DS-720D.")
    ap.add_argument("capture", help="fichier .pcap produit par USBPcapCMD")
    ap.add_argument("--adresse", help="adresse(s) USB à garder, séparées par des virgules "
                                      "(par défaut : celle où le descripteur annonce 04F9:60E2)")
    ap.add_argument("--masquer", type=entier, action="append", default=[], metavar="OPCODE",
                    help="masquer les commandes SCSI de cet opcode (ex. 0xC5), répétable")
    ap.add_argument("--octets", type=int, default=32,
                    help="octets de données affichés par ligne (-1 : tous)")
    ap.add_argument("--de", type=int, default=0, metavar="TRAME", help="première trame affichée")
    ap.add_argument("--a", type=int, default=None, metavar="TRAME", help="dernière trame affichée")
    ap.add_argument("--resume", action="store_true", help="statistiques seulement")
    ap.add_argument("--brut", action="store_true", help="en-têtes USBPcap bruts, sans décodage")
    ap.add_argument("--serie", action="store_true",
                    help="afficher le numéro de série de l'appareil (masqué par défaut)")
    ap.add_argument("--recoller", action="store_true",
                    help="rassembler en une ligne DATA-IN les morceaux d'une même phase de données "
                         "(captures de la VM, que VMware découpe ; étape 6g)")
    args = ap.parse_args()

    # La console Windows n'est pas toujours en UTF-8 ; on l'impose pour les accents.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    if args.adresse:
        adresses = {int(a) for a in args.adresse.split(",")}
    else:
        adresses, cbw_par_adresse = trouver_scanner(args.capture)
        if not adresses:
            print("Aucun descripteur 04F9:60E2 dans la capture. Adresses avec du trafic "
                  "Bulk-Only (nombre de CBW) :", file=sys.stderr)
            for adr, n in cbw_par_adresse.most_common():
                print(f"  --adresse {adr}   ({n} CBW)", file=sys.stderr)
            return 2

    dec = Decodeur(args.octets, set(args.masquer), args.serie, args.recoller)
    par_adresse = Counter()
    # Plage --de/--a, appliquée à la trame de chaque ligne et non à celle du
    # paquet qui la fait écrire : avec --recoller, la ligne DATA-IN d'une
    # phase porte la trame de son premier morceau, mais ne s'écrit qu'à la fin
    # de la phase. Une ligne de suite (SUITE) suit celle qui la précède.
    # Depuis 6i (relecture) : les morceaux écrits en fin de capture
    # ignoraient la plage.
    trame_ligne = 0

    def ecrire(lignes):
        nonlocal trame_ligne
        for l in lignes:
            if not l.startswith(SUITE):
                trame_ligne = int(l.split(None, 1)[0])
            if trame_ligne >= args.de and (args.a is None or trame_ligne <= args.a):
                print(l)

    print(f"# capture {args.capture}, adresse(s) {sorted(adresses)}")
    if not args.resume and not args.brut:
        print(f"{'# trame':<8} {'temps (s)':>12}  {'adr':>3}  {'événement':<10} détail")
    for trame in lire_pcap(args.capture):
        p = decoder_usbpcap(trame)
        if p is None:
            continue
        par_adresse[p.adresse] += 1
        if p.adresse not in adresses:
            continue
        if args.brut:
            if trame.numero >= args.de and (args.a is None or trame.numero <= args.a):
                print(decrire_brut(p))
            continue
        lignes = dec.traiter(p)
        if not args.resume:
            ecrire(lignes)
    # Morceaux restés en attente (capture arrêtée avant le CSW) : écrits quand même.
    for adr in list(dec.attente):
        lignes = dec.vider(adr)
        if not args.resume:
            ecrire(lignes)

    if args.resume:
        print(f"# trames par adresse : {dict(sorted(par_adresse.items()))}")
        print(f"# trames tronquées à la capture (snaplen) : {dec.tronques}")
        print(f"# paquets SETUP : {dec.stats['setup']}, erreurs USBD : {dec.stats['erreurs']}")
        print("# CBW par opcode, longueur et sens :")
        cbw = sorted(((k, n) for k, n in dec.stats.items() if isinstance(k, tuple) and k[0] == "CBW"),
                     key=lambda kn: -kn[1])
        for (_, op, lg, sens), n in cbw:
            print(f"#   {n:>7}  {nom_opcode(op):<28} {sens:<3} {lg:>6} o")
        csw = {k[1]: n for k, n in dec.stats.items() if isinstance(k, tuple) and k[0] == "CSW"}
        print(f"# CSW par statut : {csw}")
        print("# octets DATA-IN par opcode (longueur réelle, avant troncature) :")
        for op, n in dec.volume_in.most_common():
            print(f"#   {nom_opcode(op):<28} {n:>10} o")
        depots = sorted(((k, n) for k, n in dec.stats.items() if isinstance(k, tuple) and k[0] == "DEPOT"),
                        key=lambda kn: -kn[1])
        if depots:
            print("# commandes emballées dans 0xC5 (sélecteur 02 03 00), par opcode et taille du dépôt :")
            for (_, op, lg), n in depots:
                nom = (COMMANDES_SCANNER_DANGEREUSES.get(op, "") + " !! ÉCRITURE"
                       if op in COMMANDES_SCANNER_DANGEREUSES
                       else COMMANDES_SCANNER.get(op, (f"opcode 0x{op:02X}",))[0])
                print(f"#   {n:>7}  {nom:<28}     {lg:>6} o")
    return 0


if __name__ == "__main__":
    sys.exit(main())
