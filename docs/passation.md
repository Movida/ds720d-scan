# Passation (mise à jour le 25/10/2026, fin de l'étape 1)

Repris du projet Claude « Personnel » le 24/10, réorienté le 25/10 vers un pilote KMDF (voir [HISTORIQUE.md](../HISTORIQUE.md)). Les règles sont dans [CLAUDE.md](../CLAUDE.md).

## Reconnaissance sur Medabot (24/10, lecture seule)

| Élément | Valeur |
| --- | --- |
| USB | `VID_04F9&PID_60E2`, rév. 0100, classe 08/06/50 (Mass Storage, sous-classe SCSI transparent, protocole Bulk-Only) |
| Pilotes liés | `USBSTOR` (usbstor.inf) puis `disk` (disk.inf) ; aucun pilote Brother/NovaTek |
| INQUIRY | Vendeur « Brother », produit « DS-720D », révision « 0.27 » |
| Disque | `\\.\PhysicalDrive3`, 1 048 576 o, MBR, une partition FAT12 vide montée en **F:** |
| Logiciel Brother | `NvUSBScan.dll` 12.1.13.28 « NovaTek Msdc Ext » (System32 + SysWOW64) ; TWAIN `twain_32\Brother\DS-720D\DS-720D.ds` et `twain_64\…` ; service `Mobile_Series` actif ; `Capture Tool.exe` |

## Outils en place (25/10)

| Outil | État |
| --- | --- |
| USBPcap | Service noyau `USBPcap` RUNNING ; `C:\Program Files\USBPcap\USBPcapCMD.exe`, absent de l'extcap Wireshark, donc piloté en ligne de commande |
| Wireshark | 4.6.9 ; `C:\Program Files\Wireshark\tshark.exe` (hors PATH), sert seulement à contre-vérifier notre analyseur |
| Python | 3.14.7, pour le banc de test |
| Tâche planifiée `ds720d-capture` | Lance USBPcapCMD en admin pour Claude, depuis `C:\ProgramData\ds720d\` (voir [captures.md](captures.md)) |
| Client TWAIN de banc | `banc/twain_banc.py`, fait scanner le pilote Brother sans Capture Tool ; côté référence seulement |
| Chaîne C | **Aucune** : Build Tools Visual Studio et Windows SDK à installer par David avant l'étape 2, WDK avant l'étape 6 |

## Voie retenue

1. **Écouter** le logiciel Brother (USBPcap) pour obtenir la séquence de référence.
2. **Rejouer** en C depuis l'espace utilisateur sur WinUSB, en construisant nous-mêmes les CBW (BOT §5.1), en lisant les CSW (BOT §5.2) et les données par transferts bulk.
3. **Descendre** dans un pilote KMDF qui fait la même chose avec des URB, une fois le protocole maîtrisé.

Pourquoi pas le SCSI pass-through sur USBSTOR (voie du 24/10) : `IOCTL_SCSI_PASS_THROUGH_DIRECT` laisse Windows construire les CBW et gérer le transport, on ne voit ni les endpoints ni les transferts bulk. Contraire à l'objectif « le plus bas possible ».

Inconnue tranchée par la capture 1c : le logiciel n'écrit aucun secteur du faux disque, il emploie deux **commandes SCSI vendeur**, 0xC5 (état, réglages) et 0xC3 (lecture de l'image). Détail dans [captures.md](captures.md).

Cadre légal : l'art. L122-6-1 IV du CPI autorise l'étude d'un logiciel pour l'interopérabilité.

## Feuille de route

0. ✓ Reconnaissance (ci-dessus).
1. ✓ Captures de référence (25/10) ; notre code n'a rien envoyé au scanner, seul le logiciel Brother lui a parlé :
   - 1a. Docs alignées sur la cible KMDF.
   - 1b. Capture de l'énumération (débrancher, rebrancher).
   - 1c. Capture d'un scan avec Capture Tool (tronquée, remplacée par 1e).
   - 1d. Analyseur de captures fait main, contre-vérifié par tshark.
   - 1e. Captures pilotées par Claude (tâche planifiée, client TWAIN) : gris, couleur, noir et blanc 300 dpi, gris 600 dpi, recto-verso, « pas de papier ».
2. Passage sous WinUSB et premier programme C : descripteurs lus par transferts de contrôle (USB 2.0 §9.4.3), Get Max LUN (BOT §3.2), INQUIRY encapsulé à la main, trace de chaque transfert.
   - Prérequis : chaîne C installée par David. Piste à vérifier pour WinUSB : le pilote générique « WinUsb Device » de Windows (winusb.inf, livré avec le système), choisi à la main dans le Gestionnaire de périphériques, sans INF maison ni signature. Il coupe le logiciel Brother ; retour arrière en réinstallant USBSTOR.
3. Rejouer la séquence de scan capturée : une page gris 300 dpi en image brute, puis PGM/PNG.
4. Couleur et recto-verso.
5. Préparation noyau (accord écrit de David) : VM avec passage USB, WinDbg, test-signing, point de restauration.
6. Pilote KMDF : configuration, pipes bulk, URB, interface IOCTL vers un petit outil utilisateur, traces WPP.
7. Outil final et retrait du logiciel Brother (feu vert de David).

Accès au PC : session Remote Control sur « Medabot (claude-chrome) », dépôt dans `C:\Users\morva\claude-chrome\ds720d-scan`.
