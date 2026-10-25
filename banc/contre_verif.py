"""Contre-vérification de analyse_capture.py par tshark.

tshark (Wireshark) sert d'arbitre extérieur : on lui demande, trame par trame, les
champs CBW, CSW, SETUP et les erreurs USBD qu'il a décodés, puis on les compare à
ce que notre analyseur écrit dans sa trace. Toute divergence est listée.

tshark ne fait pas foi à notre place (CLAUDE.md) : une divergence se tranche en
relisant les octets et la spec, pas en recopiant tshark.

Usage :
  py banc/contre_verif.py CAPTURE.pcap --adresse 15 [--tshark "C:\\Program Files\\Wireshark\\tshark.exe"]
Code de sortie : 0 si tout concorde, 1 sinon.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ICI = Path(__file__).resolve().parent
TSHARK_DEFAUT = r"C:\Program Files\Wireshark\tshark.exe"


def tshark_champs(tshark, capture, filtre, champs):
    """Lance tshark et renvoie une liste de listes de valeurs (une par trame)."""
    cmd = [tshark, "-r", capture, "-Y", filtre, "-T", "fields", "-E", "separator=\t"]
    for c in champs:
        cmd += ["-e", c]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")
    if r.returncode != 0:
        raise SystemExit(f"tshark a échoué ({filtre}) : {r.stderr.strip()}")
    return [ligne.split("\t") for ligne in r.stdout.splitlines() if ligne]


def entier(v):
    """tshark écrit les nombres en décimal ou en 0x… selon le champ."""
    return int(v, 0) if v else None


def cote_tshark(tshark, capture, adresse):
    adr = f"usb.device_address == {adresse}"
    attendu = {}
    for numero, tag, lg, flags, lg_cdb, op in tshark_champs(
            tshark, capture, f"{adr} && usbms.dCBWSignature",
            ["frame.number", "usbms.dCBWTag", "usbms.dCBWDataTransferLength",
             "usbms.dCBWFlags", "usbms.dCBWCBLength", "scsi.spc.opcode"]):
        sens = "IN" if entier(flags) & 0x80 else "OUT"
        # tshark ne range pas tous les opcodes dans scsi.spc.opcode : None = non comparé.
        attendu[int(numero)] = ("CBW", entier(tag), entier(lg), sens, entier(lg_cdb), entier(op))
    for numero, tag, residu, statut in tshark_champs(
            tshark, capture, f"{adr} && usbms.dCSWSignature",
            # tshark n'a pas de champ dCSWTag : le tag d'un CSW est rangé dans dCBWTag.
            ["frame.number", "usbms.dCBWTag", "usbms.dCSWDataResidue", "usbms.dCSWStatus"]):
        attendu[int(numero)] = ("CSW", entier(tag), entier(residu), entier(statut))
    for numero, bm, req, val, idx, lg in tshark_champs(
            tshark, capture, f"{adr} && usb.control_stage == 0 && usb.irp_info.direction == 0",
            ["frame.number", "usb.bmRequestType", "usb.setup.bRequest", "usb.setup.wValue",
             "usb.setup.wIndex", "usb.setup.wLength"]):
        if bm:
            attendu[int(numero)] = ("SETUP", entier(bm), entier(req), entier(val), entier(idx), entier(lg))
    for numero, statut in tshark_champs(
            tshark, capture, f"{adr} && usb.irp_info.direction == 1 && usb.usbd_status != 0",
            ["frame.number", "usb.usbd_status"]):
        attendu[int(numero)] = ("ERREUR", entier(statut))
    return attendu


RE_LIGNE = re.compile(r"^(\d+)\s+[\d.]+\s+\d+\s+(\S+)\s+(.*)$")
RE_CBW = re.compile(r"tag=0x([0-9A-F]{8}) lun=\d+ (IN|OUT) (\d+) o  CDB\[(\d+)\]=([0-9a-f ]*)")
RE_CSW = re.compile(r"tag=0x([0-9A-F]{8}) statut=(\d+) .* résidu=(\d+)")
STATUTS = {"SUCCESS": 0, "STALL_PID": 0xC0000004, "DEV_NOT_RESPONDING": 0xC0000005,
           "CANCELED": 0xC0010000}


def cote_analyseur(capture, adresse):
    cmd = [sys.executable, "-I", str(ICI / "analyse_capture.py"), capture,
           "--adresse", str(adresse), "--octets", "0"]
    sortie = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    obtenu = {}
    for ligne in sortie.splitlines():
        m = RE_LIGNE.match(ligne)
        if not m:
            continue
        numero, evenement, detail = int(m[1]), m[2], m[3]
        if evenement == "CBW":
            c = RE_CBW.match(detail)
            cdb = bytes.fromhex(c[5])
            obtenu[numero] = ("CBW", int(c[1], 16), int(c[3]), c[2], int(c[4]), cdb[0] if cdb else None)
        elif evenement == "CSW":
            c = RE_CSW.match(detail)
            obtenu[numero] = ("CSW", int(c[1], 16), int(c[3]), int(c[2]))
        elif evenement == "SETUP":
            s = bytes.fromhex(detail[:23])
            obtenu[numero] = ("SETUP", s[0], s[1], int.from_bytes(s[2:4], "little"),
                              int.from_bytes(s[4:6], "little"), int.from_bytes(s[6:8], "little"))
        elif evenement == "ERREUR":
            nom = detail.split("USBD_STATUS_")[1].split()[0]
            obtenu[numero] = ("ERREUR", STATUTS[nom] if nom in STATUTS else int(nom, 16))
    return obtenu


def concorde(a, b):
    """Égalité champ à champ ; un champ None côté tshark n'est pas comparé."""
    return len(a) == len(b) and all(x is None or x == y for x, y in zip(a, b))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("capture")
    ap.add_argument("--adresse", type=int, required=True)
    ap.add_argument("--tshark", default=TSHARK_DEFAUT)
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    attendu = cote_tshark(args.tshark, args.capture, args.adresse)
    obtenu = cote_analyseur(args.capture, args.adresse)

    ecarts = []
    for numero in sorted(set(attendu) | set(obtenu)):
        a, o = attendu.get(numero), obtenu.get(numero)
        if a is None or o is None or not concorde(a, o):
            ecarts.append((numero, a, o))

    par_genre = {}
    for v in attendu.values():
        par_genre[v[0]] = par_genre.get(v[0], 0) + 1
    non_compares = sum(1 for v in attendu.values() if v[0] == "CBW" and v[5] is None)
    print(f"{args.capture}, adresse {args.adresse}")
    print(f"  événements vus par tshark : {dict(sorted(par_genre.items()))}")
    print(f"  événements vus par l'analyseur : {len(obtenu)}")
    print(f"  CBW dont tshark ne donne pas l'opcode (opcode non comparé) : {non_compares}")
    print(f"  écarts : {len(ecarts)}")
    for numero, a, o in ecarts[:20]:
        print(f"    trame {numero} : tshark={a} analyseur={o}")
    return 0 if not ecarts else 1


if __name__ == "__main__":
    sys.exit(main())
