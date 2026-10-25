"""Client TWAIN de banc : fait scanner le pilote Brother sans Capture Tool.

Rôle : produire les captures de référence. Ce client fait travailler le pilote
Brother (source TWAIN DS-720D), exactement comme Capture Tool, mais sans interface
et avec des réglages choisis en ligne de commande. TWAIN ne sert QUE côté
référence (accord de David du 25/10) : notre propre pilote n'y touchera jamais.

Pourquoi TWAIN plutôt qu'automatiser Capture Tool : piloter une interface graphique
(clics simulés) casse au moindre changement de fenêtre et ne donne pas accès à
tous les réglages ; l'API TWAIN expose chaque réglage (« capability ») par son code.
Pourquoi pas WIA : le DS-720D n'a pas de pilote WIA sur Medabot, seulement TWAIN.

Source : spécification TWAIN 2.4 (twain.org) et son en-tête twain.h, d'où viennent
les structures (alignées sur 2 octets sous Windows) et les constantes ci-dessous.

Usage :
  py banc/twain_banc.py lister
  py banc/twain_banc.py scanner --mode gris --dpi 300 [--recto-verso] [--regle 0x8001=2]
                                [--capture NOM] [--sortie DOSSIER]
"""

import argparse
import ctypes
import struct
import sys
import time
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture  # noqa: E402  (module voisin : pilotage de la tâche de capture)

# ---------------------------------------------------------------------------
# Constantes TWAIN (twain.h)
# ---------------------------------------------------------------------------

DG_CONTROL, DG_IMAGE = 0x0001, 0x0002
DF_DSM2, DF_APP2, DF_DS2 = 0x10000000, 0x20000000, 0x40000000

DAT_CAPABILITY, DAT_EVENT, DAT_IDENTITY, DAT_PARENT = 0x0001, 0x0002, 0x0003, 0x0004
DAT_PENDINGXFERS, DAT_STATUS, DAT_USERINTERFACE = 0x0005, 0x0008, 0x0009
DAT_SETUPFILEXFER, DAT_IMAGEINFO, DAT_IMAGEFILEXFER = 0x0007, 0x0101, 0x0105

MSG_GET, MSG_GETCURRENT, MSG_SET = 0x0001, 0x0002, 0x0006
MSG_GETFIRST, MSG_GETNEXT = 0x0004, 0x0005
MSG_XFERREADY, MSG_CLOSEDSREQ, MSG_CLOSEDSOK = 0x0101, 0x0102, 0x0103
MSG_OPENDSM, MSG_CLOSEDSM = 0x0301, 0x0302
MSG_OPENDS, MSG_CLOSEDS = 0x0401, 0x0402
MSG_DISABLEDS, MSG_ENABLEDS = 0x0501, 0x0502
MSG_PROCESSEVENT, MSG_ENDXFER = 0x0601, 0x0701

TWRC = {0: "SUCCESS", 1: "FAILURE", 2: "CHECKSTATUS", 3: "CANCEL", 4: "DSEVENT",
        5: "NOTDSEVENT", 6: "XFERDONE", 7: "ENDOFLIST"}
TWRC_SUCCESS, TWRC_FAILURE, TWRC_CHECKSTATUS, TWRC_CANCEL = 0, 1, 2, 3
TWRC_NOTDSEVENT, TWRC_XFERDONE, TWRC_ENDOFLIST = 5, 6, 7

TWON_ARRAY, TWON_ENUMERATION, TWON_ONEVALUE, TWON_RANGE = 3, 4, 5, 6
NOMS_CONTENEUR = {3: "ARRAY", 4: "ENUMERATION", 5: "ONEVALUE", 6: "RANGE"}

# Types d'éléments : (format struct, taille en octets, nom).
TWTY = {
    0x0: ("b", 1, "INT8"), 0x1: ("h", 2, "INT16"), 0x2: ("i", 4, "INT32"),
    0x3: ("B", 1, "UINT8"), 0x4: ("H", 2, "UINT16"), 0x5: ("I", 4, "UINT32"),
    0x6: ("H", 2, "BOOL"), 0x7: (None, 4, "FIX32"), 0x8: (None, 16, "FRAME"),
    0x9: (None, 34, "STR32"), 0xA: (None, 66, "STR64"), 0xB: (None, 130, "STR128"),
    0xC: (None, 256, "STR255"), 0xF: ("Q", 8, "HANDLE"),
}
TWTY_UINT16, TWTY_BOOL, TWTY_FIX32 = 0x4, 0x6, 0x7

# Noms des réglages courants ; les autres s'affichent en hexadécimal.
# Les codes à partir de 0x8000 sont propres au fabricant (CAP_CUSTOMBASE).
NOMS_CAP = {
    0x0001: "CAP_XFERCOUNT", 0x0100: "ICAP_COMPRESSION", 0x0101: "ICAP_PIXELTYPE",
    0x0102: "ICAP_UNITS", 0x0103: "ICAP_XFERMECH",
    0x1000: "CAP_AUTHOR", 0x1001: "CAP_CAPTION", 0x1002: "CAP_FEEDERENABLED",
    0x1003: "CAP_FEEDERLOADED", 0x1004: "CAP_TIMEDATE", 0x1005: "CAP_SUPPORTEDCAPS",
    0x1006: "CAP_EXTENDEDCAPS", 0x1007: "CAP_AUTOFEED", 0x1008: "CAP_CLEARPAGE",
    0x1009: "CAP_FEEDPAGE", 0x100A: "CAP_REWINDPAGE", 0x100B: "CAP_INDICATORS",
    0x100D: "CAP_PAPERDETECTABLE", 0x100E: "CAP_UICONTROLLABLE", 0x100F: "CAP_DEVICEONLINE",
    0x1010: "CAP_AUTOSCAN", 0x1011: "CAP_THUMBNAILSENABLED", 0x1012: "CAP_DUPLEX",
    0x1013: "CAP_DUPLEXENABLED", 0x1014: "CAP_ENABLEDSUIONLY",
    0x1100: "ICAP_AUTOBRIGHT", 0x1101: "ICAP_BRIGHTNESS", 0x1103: "ICAP_CONTRAST",
    0x1104: "ICAP_CUSTHALFTONE", 0x1105: "ICAP_EXPOSURETIME", 0x1106: "ICAP_FILTER",
    0x1107: "ICAP_FLASHUSED", 0x1108: "ICAP_GAMMA", 0x1109: "ICAP_HALFTONES",
    0x110A: "ICAP_HIGHLIGHT", 0x110C: "ICAP_IMAGEFILEFORMAT", 0x110D: "ICAP_LAMPSTATE",
    0x110E: "ICAP_LIGHTSOURCE", 0x1110: "ICAP_ORIENTATION", 0x1111: "ICAP_PHYSICALWIDTH",
    0x1112: "ICAP_PHYSICALHEIGHT", 0x1113: "ICAP_SHADOW", 0x1114: "ICAP_FRAMES",
    0x1116: "ICAP_XNATIVERESOLUTION", 0x1117: "ICAP_YNATIVERESOLUTION",
    0x1118: "ICAP_XRESOLUTION", 0x1119: "ICAP_YRESOLUTION", 0x111A: "ICAP_MAXFRAMES",
    0x111B: "ICAP_TILES", 0x111C: "ICAP_BITORDER", 0x111D: "ICAP_CCITTKFACTOR",
    0x111E: "ICAP_LIGHTPATH", 0x111F: "ICAP_PIXELFLAVOR", 0x1120: "ICAP_PLANARCHUNKY",
    0x1121: "ICAP_ROTATION", 0x1122: "ICAP_SUPPORTEDSIZES", 0x1123: "ICAP_THRESHOLD",
    0x1124: "ICAP_XSCALING", 0x1125: "ICAP_YSCALING", 0x1126: "ICAP_BITORDERCODES",
    0x1127: "ICAP_PIXELFLAVORCODES", 0x1128: "ICAP_JPEGPIXELTYPE", 0x112A: "ICAP_TIMEFILL",
    0x112B: "ICAP_BITDEPTH", 0x112C: "ICAP_BITDEPTHREDUCTION",
    0x112D: "ICAP_UNDEFINEDIMAGESIZE", 0x112E: "ICAP_IMAGEDATASET",
    0x112F: "ICAP_EXTIMAGEINFO", 0x1130: "ICAP_MINIMUMHEIGHT", 0x1131: "ICAP_MINIMUMWIDTH",
}
ICAP_PIXELTYPE, ICAP_XRESOLUTION, ICAP_YRESOLUTION = 0x0101, 0x1118, 0x1119
ICAP_XFERMECH, ICAP_IMAGEFILEFORMAT = 0x0103, 0x110C
CAP_SUPPORTEDCAPS, CAP_DUPLEXENABLED = 0x1005, 0x1013
TWPT = {"nb": 0, "gris": 1, "couleur": 2}  # ICAP_PIXELTYPE : BW, GRAY, RGB
# Transfert par fichier (TWSX_FILE) au format BMP (TWFF_BMP). Pourquoi pas le transfert
# natif (TWSX_NATIVE, le plus courant) : le 25/10, la source Brother 64 bits a rendu
# un handle tronqué à 32 bits (0xF7EC0058) que GlobalLock refuse. Pourquoi pas le
# transfert mémoire (TWSX_MEMORY) : plus de code pour le même résultat.
TWSX_FILE, TWFF_BMP = 1, 2


def nom_cap(code):
    if code in NOMS_CAP:
        return NOMS_CAP[code]
    return f"PERSO_0x{code:04X}" if code >= 0x8000 else f"CAP_0x{code:04X}"


# ---------------------------------------------------------------------------
# Structures (twain.h : #pragma pack(2) sous Windows)
# ---------------------------------------------------------------------------

class TW_VERSION(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("MajorNum", ctypes.c_uint16), ("MinorNum", ctypes.c_uint16),
                ("Language", ctypes.c_uint16), ("Country", ctypes.c_uint16),
                ("Info", ctypes.c_char * 34)]


class TW_IDENTITY(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("Id", ctypes.c_uint32), ("Version", TW_VERSION),
                ("ProtocolMajor", ctypes.c_uint16), ("ProtocolMinor", ctypes.c_uint16),
                ("SupportedGroups", ctypes.c_uint32),
                ("Manufacturer", ctypes.c_char * 34), ("ProductFamily", ctypes.c_char * 34),
                ("ProductName", ctypes.c_char * 34)]


class TW_CAPABILITY(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("Cap", ctypes.c_uint16), ("ConType", ctypes.c_uint16),
                ("hContainer", ctypes.c_void_p)]


class TW_USERINTERFACE(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("ShowUI", ctypes.c_uint16), ("ModalUI", ctypes.c_uint16),
                ("hParent", ctypes.c_void_p)]


class TW_EVENT(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("pEvent", ctypes.c_void_p), ("TWMessage", ctypes.c_uint16)]


class TW_PENDINGXFERS(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("Count", ctypes.c_uint16), ("EOJ", ctypes.c_uint32)]


class TW_STATUS(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("ConditionCode", ctypes.c_uint16), ("Data", ctypes.c_uint16)]


class TW_SETUPFILEXFER(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("FileName", ctypes.c_char * 256), ("Format", ctypes.c_uint16),
                ("VRefNum", ctypes.c_int16)]


class TW_FIX32(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("Whole", ctypes.c_int16), ("Frac", ctypes.c_uint16)]


class TW_IMAGEINFO(ctypes.Structure):
    _pack_ = 2
    _fields_ = [("XResolution", TW_FIX32), ("YResolution", TW_FIX32),
                ("ImageWidth", ctypes.c_int32), ("ImageLength", ctypes.c_int32),
                ("SamplesPerPixel", ctypes.c_int16), ("BitsPerSample", ctypes.c_int16 * 8),
                ("BitsPerPixel", ctypes.c_int16), ("Planar", ctypes.c_uint16),
                ("PixelType", ctypes.c_int16), ("Compression", ctypes.c_uint16)]


def fix32_vers_float(brut):
    entier, frac = struct.unpack("<hH", struct.pack("<I", brut))
    return entier + frac / 65536


def float_vers_fix32(valeur):
    entier = int(valeur)
    frac = int(round((valeur - entier) * 65536)) & 0xFFFF
    return struct.unpack("<I", struct.pack("<hH", entier, frac))[0]


# ---------------------------------------------------------------------------
# Windows : mémoire globale, fenêtre parente, boucle de messages
# ---------------------------------------------------------------------------

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
kernel32.GlobalAlloc.restype = ctypes.c_void_p
kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
kernel32.GlobalFree.argtypes = [ctypes.c_void_p]
kernel32.GlobalSize.argtypes = [ctypes.c_void_p]
kernel32.GlobalSize.restype = ctypes.c_size_t
user32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                   wintypes.DWORD, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, wintypes.HWND, wintypes.HMENU,
                                   wintypes.HINSTANCE, wintypes.LPVOID]
user32.CreateWindowExW.restype = wintypes.HWND
user32.PeekMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                                wintypes.UINT, wintypes.UINT, wintypes.UINT]
user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
user32.DestroyWindow.argtypes = [wintypes.HWND]
GHND = 0x0042  # GMEM_MOVEABLE | GMEM_ZEROINIT
PM_REMOVE = 0x0001

# Le gestionnaire TWAIN 2.x (twaindsm.dll) 64 bits, livré dans System32.
# Pourquoi GlobalAlloc et pas DSM_MemAllocate : sous Windows, le DSM alloue lui-même
# avec GlobalAlloc ; passer par ses points d'entrée n'apporte rien ici.
twaindsm = ctypes.WinDLL(r"C:\Windows\System32\twaindsm.dll")
DSM_Entry = twaindsm.DSM_Entry
DSM_Entry.argtypes = [ctypes.POINTER(TW_IDENTITY), ctypes.POINTER(TW_IDENTITY),
                      ctypes.c_uint32, ctypes.c_uint16, ctypes.c_uint16, ctypes.c_void_p]
DSM_Entry.restype = ctypes.c_uint16


# ---------------------------------------------------------------------------
# Session TWAIN
# ---------------------------------------------------------------------------

class ErreurTwain(Exception):
    pass


class Session:
    """Ouvre le gestionnaire (état 3) puis la source DS-720D (état 4) ; les ferme en sortie."""

    def __init__(self):
        self.app = TW_IDENTITY()
        self.app.Version.MajorNum, self.app.Version.MinorNum = 1, 0
        self.app.Version.Language, self.app.Version.Country = 13, 1  # TWLG_USA, TWCY_USA
        self.app.Version.Info = b"banc ds720d-scan"
        self.app.ProtocolMajor, self.app.ProtocolMinor = 2, 4
        self.app.SupportedGroups = DG_CONTROL | DG_IMAGE | DF_APP2
        self.app.Manufacturer = b"ds720d-scan"
        self.app.ProductFamily = b"banc"
        self.app.ProductName = b"twain_banc"
        self.source = None
        self.hwnd = user32.CreateWindowExW(0, "STATIC", "twain_banc", 0, 0, 0, 0, 0,
                                           None, None, None, None)

    def appel(self, dg, dat, msg, donnees, source=True):
        dest = ctypes.byref(self.source) if source and self.source is not None else None
        ptr = ctypes.cast(ctypes.byref(donnees), ctypes.c_void_p) if donnees is not None else None
        return DSM_Entry(ctypes.byref(self.app), dest, dg, dat, msg, ptr)

    def statut(self, source=True):
        s = TW_STATUS()
        self.appel(DG_CONTROL, DAT_STATUS, MSG_GET, s, source)
        return s.ConditionCode

    def verifier(self, rc, quoi, source=True):
        if rc not in (TWRC_SUCCESS, TWRC_CHECKSTATUS):
            raise ErreurTwain(f"{quoi} : {TWRC.get(rc, rc)}, condition {self.statut(source)}")
        return rc

    def __enter__(self):
        h = wintypes.HWND(self.hwnd)
        self.verifier(self.appel(DG_CONTROL, DAT_PARENT, MSG_OPENDSM, h, source=False),
                      "ouverture du gestionnaire", source=False)
        self.source = self.trouver_source()
        self.verifier(self.appel(DG_CONTROL, DAT_IDENTITY, MSG_OPENDS, self.source, source=False),
                      "ouverture de la source", source=False)
        return self

    def __exit__(self, *exc):
        if self.source is not None:
            self.appel(DG_CONTROL, DAT_IDENTITY, MSG_CLOSEDS, self.source, source=False)
        h = wintypes.HWND(self.hwnd)
        self.appel(DG_CONTROL, DAT_PARENT, MSG_CLOSEDSM, h, source=False)
        user32.DestroyWindow(self.hwnd)

    def trouver_source(self):
        ident = TW_IDENTITY()
        rc = self.appel(DG_CONTROL, DAT_IDENTITY, MSG_GETFIRST, ident, source=False)
        vues = []
        while rc == TWRC_SUCCESS:
            vues.append(ident.ProductName.decode(errors="replace"))
            if b"DS-720D" in ident.ProductName:
                trouvee = TW_IDENTITY()
                ctypes.memmove(ctypes.byref(trouvee), ctypes.byref(ident), ctypes.sizeof(ident))
                return trouvee
            rc = self.appel(DG_CONTROL, DAT_IDENTITY, MSG_GETNEXT, ident, source=False)
        raise ErreurTwain(f"source DS-720D introuvable ; sources vues : {vues}")

    # --- réglages (capabilities) ---

    def lire_cap(self, code, msg=MSG_GET):
        """Renvoie (conteneur, type, contenu) ; le contenu dépend du conteneur."""
        cap = TW_CAPABILITY(Cap=code, ConType=0, hContainer=None)
        rc = self.appel(DG_CONTROL, DAT_CAPABILITY, msg, cap)
        if rc != TWRC_SUCCESS:
            raise ErreurTwain(f"lecture {nom_cap(code)} : {TWRC.get(rc, rc)}, condition {self.statut()}")
        try:
            ptr = kernel32.GlobalLock(cap.hContainer)
            brut = ctypes.string_at(ptr, kernel32.GlobalSize(cap.hContainer))
            kernel32.GlobalUnlock(cap.hContainer)
        finally:
            kernel32.GlobalFree(cap.hContainer)
        return cap.ConType, *decoder_conteneur(cap.ConType, brut)

    def ecrire_cap(self, code, type_item, valeur):
        """MSG_SET avec un TW_ONEVALUE : ItemType (2 o) puis Item (4 o)."""
        h = kernel32.GlobalAlloc(GHND, 6)
        ptr = kernel32.GlobalLock(h)
        ctypes.memmove(ptr, struct.pack("<HI", type_item, valeur), 6)
        kernel32.GlobalUnlock(h)
        cap = TW_CAPABILITY(Cap=code, ConType=TWON_ONEVALUE, hContainer=h)
        try:
            rc = self.appel(DG_CONTROL, DAT_CAPABILITY, MSG_SET, cap)
        finally:
            kernel32.GlobalFree(h)
        self.verifier(rc, f"réglage {nom_cap(code)}")
        return rc


def lire_item(brut, decalage, type_item):
    fmt, taille, _ = TWTY.get(type_item, ("I", 4, "?"))
    octets = brut[decalage:decalage + taille]
    if type_item == TWTY_FIX32:
        return round(fix32_vers_float(struct.unpack("<I", octets)[0]), 4)
    if fmt is None:
        return octets.split(b"\0")[0].decode(errors="replace") if type_item >= 0x9 else octets.hex()
    return struct.unpack("<" + fmt, octets)[0]


def decoder_conteneur(contype, brut):
    type_item = struct.unpack_from("<H", brut)[0]
    taille = TWTY.get(type_item, (None, 4))[1]
    if contype == TWON_ONEVALUE:
        return type_item, lire_item(brut, 2, type_item)
    if contype == TWON_ENUMERATION:
        n, courant, defaut = struct.unpack_from("<III", brut, 2)
        valeurs = [lire_item(brut, 14 + i * taille, type_item) for i in range(n)]
        return type_item, {"valeurs": valeurs, "courant": valeurs[courant] if courant < n else None,
                           "défaut": valeurs[defaut] if defaut < n else None}
    if contype == TWON_RANGE:
        mini, maxi, pas, defaut, courant = struct.unpack_from("<IIIII", brut, 2)
        conv = (lambda v: round(fix32_vers_float(v), 4)) if type_item == TWTY_FIX32 else (lambda v: v)
        return type_item, {"min": conv(mini), "max": conv(maxi), "pas": conv(pas),
                           "défaut": conv(defaut), "courant": conv(courant)}
    if contype == TWON_ARRAY:
        n = struct.unpack_from("<I", brut, 2)[0]
        return type_item, [lire_item(brut, 6 + i * taille, type_item) for i in range(n)]
    return type_item, brut.hex()


# ---------------------------------------------------------------------------
# Commandes
# ---------------------------------------------------------------------------

def lister():
    with Session() as s:
        src = s.source
        print(f"Source : {src.Manufacturer.decode()} / {src.ProductName.decode()} "
              f"v{src.Version.MajorNum}.{src.Version.MinorNum} « {src.Version.Info.decode(errors='replace')} », "
              f"protocole {src.ProtocolMajor}.{src.ProtocolMinor}, "
              f"groupes 0x{src.SupportedGroups:08X}")
        _, _, codes = s.lire_cap(CAP_SUPPORTEDCAPS)
        for code in sorted(codes):
            try:
                contype, type_item, contenu = s.lire_cap(code)
                print(f"0x{code:04X} {nom_cap(code):<28} {NOMS_CONTENEUR.get(contype, contype):<11} "
                      f"{TWTY.get(type_item, (0, 0, hex(type_item)))[2]:<6} {contenu}")
            except ErreurTwain as e:
                print(f"0x{code:04X} {nom_cap(code):<28} (illisible : {e})")


def valeur_regle(type_item, texte):
    if type_item == TWTY_FIX32:
        return float_vers_fix32(float(texte))
    return int(texte, 0)


def dimensions_bmp(chemin):
    """Largeur, hauteur et bits par pixel lus dans le BITMAPINFOHEADER du fichier."""
    with open(chemin, "rb") as f:
        entete = f.read(30)
    largeur, hauteur, _, bits = struct.unpack_from("<iiHH", entete, 18)
    return largeur, abs(hauteur), bits


def scanner(args):
    sortie = Path(args.sortie)
    sortie.mkdir(parents=True, exist_ok=True)
    base = args.capture or time.strftime("scan-%Y%m%d-%H%M%S")
    with Session() as s:
        # Réglages, chacun cité par son code TWAIN.
        s.ecrire_cap(ICAP_PIXELTYPE, TWTY_UINT16, TWPT[args.mode])
        s.ecrire_cap(ICAP_XRESOLUTION, TWTY_FIX32, float_vers_fix32(args.dpi))
        s.ecrire_cap(ICAP_YRESOLUTION, TWTY_FIX32, float_vers_fix32(args.dpi))
        s.ecrire_cap(CAP_DUPLEXENABLED, TWTY_BOOL, 1 if args.recto_verso else 0)
        s.ecrire_cap(ICAP_XFERMECH, TWTY_UINT16, TWSX_FILE)
        s.ecrire_cap(ICAP_IMAGEFILEFORMAT, TWTY_UINT16, TWFF_BMP)
        for regle in args.regle:
            code_txt, valeur_txt = regle.split("=", 1)
            code = int(code_txt, 0)
            _, type_item, _ = s.lire_cap(code, MSG_GETCURRENT)
            s.ecrire_cap(code, type_item, valeur_regle(type_item, valeur_txt))
            print(f"réglage {nom_cap(code)} = {valeur_txt}")

        if args.capture:
            print(capture.demarrer(args.capture, duree=args.duree))
        try:
            images = acquerir(s, sortie, base, args.delai)
        finally:
            if args.capture:
                time.sleep(1.0)  # laisser passer les derniers échanges après le scan
                print(capture.arreter(args.capture))
    for chemin, (l, h, bits) in images:
        print(f"image {chemin} : {l} x {h}, {bits} bits par pixel")


def acquerir(s, sortie, base, delai):
    """États 5 à 7 : active la source sans interface, attend MSG_XFERREADY dans la
    boucle de messages, transfère chaque image dans un fichier BMP, puis désactive."""
    ui = TW_USERINTERFACE(ShowUI=0, ModalUI=0, hParent=s.hwnd)
    s.verifier(s.appel(DG_CONTROL, DAT_USERINTERFACE, MSG_ENABLEDS, ui), "activation de la source")
    images = []
    msg = wintypes.MSG()
    limite = time.monotonic() + delai
    fini = False
    try:
        while not fini:
            if time.monotonic() > limite:
                raise ErreurTwain(f"aucune image après {delai} s (feuille insérée ?)")
            if not user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, PM_REMOVE):
                time.sleep(0.01)
                continue
            ev = TW_EVENT(pEvent=ctypes.cast(ctypes.byref(msg), ctypes.c_void_p), TWMessage=0)
            rc = s.appel(DG_CONTROL, DAT_EVENT, MSG_PROCESSEVENT, ev)
            if ev.TWMessage == MSG_XFERREADY:
                images += transferer(s, sortie, base, len(images))
                fini = True
            elif ev.TWMessage in (MSG_CLOSEDSREQ, MSG_CLOSEDSOK):
                fini = True
            if rc == TWRC_NOTDSEVENT:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
    finally:
        s.appel(DG_CONTROL, DAT_USERINTERFACE, MSG_DISABLEDS, ui)
    return images


def transferer(s, sortie, base, deja):
    images = []
    en_attente = TW_PENDINGXFERS(Count=1)
    while en_attente.Count != 0:
        info = TW_IMAGEINFO()
        s.appel(DG_IMAGE, DAT_IMAGEINFO, MSG_GET, info)
        print(f"image annoncée : {info.ImageWidth} x {info.ImageLength}, "
              f"{info.BitsPerPixel} bits par pixel, {info.XResolution.Whole} dpi")
        chemin = sortie / f"{base}-{deja + len(images) + 1}.bmp"
        fichier = TW_SETUPFILEXFER(FileName=str(chemin).encode("mbcs"), Format=TWFF_BMP, VRefNum=0)
        s.verifier(s.appel(DG_CONTROL, DAT_SETUPFILEXFER, MSG_SET, fichier), "choix du fichier")
        rc = s.appel(DG_IMAGE, DAT_IMAGEFILEXFER, MSG_GET, None)
        if rc == TWRC_XFERDONE:
            images.append((chemin, dimensions_bmp(chemin)))
        elif rc == TWRC_CANCEL:
            print("transfert annulé par la source")
        else:
            raise ErreurTwain(f"transfert : {TWRC.get(rc, rc)}, condition {s.statut()}")
        s.appel(DG_CONTROL, DAT_PENDINGXFERS, MSG_ENDXFER, en_attente)
    return images


def main():
    ap = argparse.ArgumentParser(description="Client TWAIN de banc pour le DS-720D (référence Brother).")
    sous = ap.add_subparsers(dest="action", required=True)
    sous.add_parser("lister", help="lister les réglages de la source et leurs valeurs")
    sc = sous.add_parser("scanner", help="scanner sans interface")
    sc.add_argument("--mode", choices=TWPT, default="gris")
    sc.add_argument("--dpi", type=float, default=300)
    sc.add_argument("--recto-verso", action="store_true")
    sc.add_argument("--regle", action="append", default=[], metavar="CODE=VALEUR",
                    help="réglage supplémentaire, ex. 0x1101=20 (répétable)")
    sc.add_argument("--capture", metavar="NOM", help="encadrer le scan d'une capture USBPcap NOM.pcap")
    sc.add_argument("--duree", type=int, default=300, help="durée maximale de la capture (s)")
    sc.add_argument("--delai", type=float, default=120, help="attente maximale de l'image (s)")
    sc.add_argument("--sortie", default=r"C:\Users\morva\ds720d-captures\images",
                    help="dossier des images (hors dépôt : elles montrent des documents)")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        lister() if args.action == "lister" else scanner(args)
    except ErreurTwain as e:
        print(f"erreur TWAIN : {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
