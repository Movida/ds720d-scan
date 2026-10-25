# Historique

Journal des étapes et des décisions, du plus ancien au plus récent.

## 24/10/2026 — Étape 0 : reconnaissance

- Recherche de l'existant : aucun pilote libre du DS-720D. Le DS-620 voisin s'annonce en USB Mass Storage ; Brother lui parle en SCSI brut sous Linux (`libsane-dsseries`, binaire fermé). Le backend SANE `avision` documente le jeu de commandes de l'OEM Avision.
- Reconnaissance en lecture seule sur Medabot : Mass Storage Bulk-Only, faux disque FAT12 de 1 Mo en F:, INQUIRY « Brother DS-720D 0.27 », pilote Brother `NvUSBScan.dll` (NovaTek).
- Voie choisie ce jour-là : SCSI pass-through sur USBSTOR depuis Python, sans pilote noyau.
- Installation par David de USBPcap, Wireshark 4.6.9 et Python 3.14.7.

## 25/10/2026 — Étape 1 : captures de référence

- **Décision** : cible finale un pilote noyau KMDF écrit en C, bas niveau partout. Une phase en espace utilisateur sur WinUSB sert d'abord à apprendre le protocole sans risquer d'écran bleu. Abandon du SCSI pass-through, qui cache le transport BOT.
- Conséquence : passer sous WinUSB coupe le logiciel Brother, donc toutes les captures de référence se font avant.
- Après redémarrage de Medabot : service `USBPcap` RUNNING, `USBPcapCMD.exe` présent. Aucune chaîne de compilation C installée.
- 1a : docs alignées (CLAUDE.md, passation, création de cet historique).
- 1b : capture de l'énumération (registre dans [docs/captures.md](docs/captures.md)). Premières observations : le logiciel Brother interroge le scanner en boucle avec une commande vendeur **0xC5**, environ 50 fois par seconde ; Windows envoie INQUIRY puis READ FORMAT CAPACITIES, que le scanner refuse (STALL puis REQUEST SENSE).
