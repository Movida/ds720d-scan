"""Analyseur de captures USBPcap, écrit à la main (bibliothèque standard seulement).

Lit un fichier .pcap produit par USBPcapCMD et décode, couche par couche :
  1. le format pcap (en-tête global, en-têtes d'enregistrement) ;
  2. l'en-tête USBPcap de chaque paquet (URB vu par le filtre USBPcap) ;
  3. les transferts de contrôle (paquet SETUP, USB 2.0 §9.3) et les descripteurs (§9.6) ;
  4. le transport Bulk-Only (CBW BOT §5.1, CSW BOT §5.2) et les commandes SCSI encapsulées.

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

    def __init__(self, octets_max, masques, montrer_serie=False):
        self.octets_max = octets_max
        self.masques = masques
        self.montrer_serie = montrer_serie
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
        if p.statut != 0 and p.retour:
            self.stats["erreurs"] += 1
            sortie = [self.ligne(p, "ERREUR",
                                 f"ep=0x{p.endpoint:02X} {NOMS_TRANSFERT.get(t, t)} "
                                 f"USBD_STATUS_{nom_statut(p.statut)}")]
        else:
            sortie = []
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
                _, tag, lg, flags, lun, lg_cdb, cdb = CBW.unpack(d)
                cdb = cdb[:lg_cdb]
                op = cdb[0] if cdb else -1
                self.cbw[p.adresse] = (tag, op, cdb)
                sens = "IN" if flags & 0x80 else "OUT"
                self.stats[("CBW", op, lg, sens)] += 1
                if op in self.masques:
                    return []
                return [self.ligne(p, "CBW", f"tag=0x{tag:08X} lun={lun} {sens} {lg} o  "
                                             f"CDB[{lg_cdb}]={cdb.hex(' ')}  {nom_opcode(op)}")]
            if d:
                self.stats["data-out"] += 1
                if self.masque(p):
                    return []
                return [self.ligne(p, "DATA-OUT", f"{len(d)} o  {hexa(d, self.octets_max)}")]
            return []
        if entrant and p.retour and (d or p.longueur_donnees):
            # Complétion IN : les octets arrivent du scanner.
            cour = self.cbw.get(p.adresse)
            if len(d) == CSW.size and d[:4] == b"USBS":
                _, tag, residu, statut = CSW.unpack(d)
                attendu = cour[0] if cour else None
                masque = self.masque(p)
                self.cbw.pop(p.adresse, None)
                self.stats[("CSW", statut)] += 1
                if masque:
                    return []
                alerte = "" if tag == attendu else f"  !! tag inattendu (CBW 0x{attendu or 0:08X})"
                return [self.ligne(p, "CSW", f"tag=0x{tag:08X} statut={statut} "
                                             f"({STATUTS_CSW.get(statut, '?')}) résidu={residu}{alerte}")]
            if cour:
                self.volume_in[cour[1]] += p.longueur_donnees
            self.stats["data-in"] += 1
            if self.masque(p):
                return []
            tronque = f" (capturés {len(d)})" if p.tronque else ""
            lignes = [self.ligne(p, "DATA-IN", f"{p.longueur_donnees} o{tronque}  {hexa(d, self.octets_max)}")]
            if cour:
                lignes += [SUITE + l for l in decrire_reponse_scsi(cour[2], d)]
            return lignes
        return []


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

    dec = Decodeur(args.octets, set(args.masquer), args.serie)
    par_adresse = Counter()
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
        if not args.resume and trame.numero >= args.de and (args.a is None or trame.numero <= args.a):
            for l in lignes:
                print(l)

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
    return 0


if __name__ == "__main__":
    sys.exit(main())
