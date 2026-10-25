"""Démarre et arrête une capture USBPcap sans droits admin, via la tâche planifiée.

La tâche « ds720d-capture » exécute banc/capture_admin.ps1 avec les droits admin
(installation : docs/captures.md). Ce module ne fait que déposer les fichiers
convenus dans le dossier des captures et lire le journal :
  demande.txt  nom, concentrateur et durée maximale de la capture ;
  stop         demande d'arrêt ;
  capture.log  « début NOM … » puis « fin NOM (taille o) », ou « refus : … ».

Usage :
  py banc/capture.py demarrer NOM [--hub 1] [--duree 300]
  py banc/capture.py arreter NOM
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

DOSSIER = Path(r"C:\Users\morva\ds720d-captures")
DEMANDE = DOSSIER / "demande.txt"
STOP = DOSSIER / "stop"
JOURNAL = DOSSIER / "capture.log"
TACHE = "ds720d-capture"


def lignes_journal():
    if not JOURNAL.exists():
        return []
    # Add-Content -Encoding utf8 de PowerShell 5.1 écrit une marque d'ordre (BOM).
    return JOURNAL.read_text(encoding="utf-8-sig", errors="replace").splitlines()


def attendre_ligne(depart, predicat, delai):
    """Attend qu'une nouvelle ligne du journal (au-delà de « depart ») vérifie le
    prédicat ; renvoie cette ligne, ou None après « delai » secondes."""
    limite = time.monotonic() + delai
    while time.monotonic() < limite:
        for ligne in lignes_journal()[depart:]:
            if predicat(ligne):
                return ligne
        time.sleep(0.2)
    return None


def demarrer(nom, hub=1, duree=300):
    depart = len(lignes_journal())
    DEMANDE.write_text(f"nom={nom}\nhub={hub}\nduree={duree}\n", encoding="ascii")
    subprocess.run(["schtasks", "/run", "/tn", TACHE], check=True, capture_output=True)
    ligne = attendre_ligne(depart, lambda l: f" début {nom} " in l or " refus : " in l, 20)
    if ligne is None or " refus : " in ligne:
        raise RuntimeError(f"capture non démarrée : {ligne or 'aucune réponse de la tâche'}")
    # USBPcapCMD met un instant à ouvrir le pilote et à écrire l'en-tête pcap.
    time.sleep(1.5)
    return ligne


def arreter(nom):
    depart = len(lignes_journal())
    STOP.touch()
    ligne = attendre_ligne(depart, lambda l: f" fin {nom} " in l, 20)
    if ligne is None:
        raise RuntimeError("la tâche n'a pas confirmé l'arrêt (voir capture.log)")
    return ligne


def main():
    ap = argparse.ArgumentParser(description="Capture USBPcap via la tâche planifiée.")
    sous = ap.add_subparsers(dest="action", required=True)
    d = sous.add_parser("demarrer")
    d.add_argument("nom")
    d.add_argument("--hub", type=int, default=1)
    d.add_argument("--duree", type=int, default=300)
    a = sous.add_parser("arreter")
    a.add_argument("nom")
    args = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.action == "demarrer":
        print(demarrer(args.nom, args.hub, args.duree))
    else:
        print(arreter(args.nom))


if __name__ == "__main__":
    main()
