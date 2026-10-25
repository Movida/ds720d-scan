# Passation (mise à jour le 25/10/2026)

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
| Chaîne C | **Aucune** (ni MSVC, ni WDK) : à installer par David avant l'étape 2 |

## Voie retenue

1. **Écouter** le logiciel Brother (USBPcap) pour obtenir la séquence de référence.
2. **Rejouer** en C depuis l'espace utilisateur sur WinUSB, en construisant nous-mêmes les CBW (BOT §5.1), en lisant les CSW (BOT §5.2) et les données par transferts bulk.
3. **Descendre** dans un pilote KMDF qui fait la même chose avec des URB, une fois le protocole maîtrisé.

Pourquoi pas le SCSI pass-through sur USBSTOR (voie du 24/10) : `IOCTL_SCSI_PASS_THROUGH_DIRECT` laisse Windows construire les CBW et gérer le transport, on ne voit ni les endpoints ni les transferts bulk. Contraire à l'objectif « le plus bas possible ».

Inconnue principale : le logiciel envoie-t-il des **commandes SCSI propriétaires** (style Avision : SET WINDOW 0x24, READ 0x28…) ou **lit-il et écrit-il des secteurs précis** du faux disque (méthode « MSDC » courante chez NovaTek) ? La capture 1c tranche. Si c'est la seconde, l'écriture de secteurs heurte la règle « jamais écrire sur F: » : décision à prendre avec David avant d'envoyer quoi que ce soit.

Cadre légal : l'art. L122-6-1 IV du CPI autorise l'étude d'un logiciel pour l'interopérabilité.

## Feuille de route

0. ✓ Reconnaissance (ci-dessus).
1. Captures de référence, rien n'est envoyé au scanner :
   - 1a. Docs alignées sur la cible KMDF.
   - 1b. Capture de l'énumération (débrancher, rebrancher).
   - 1c. Capture d'un scan avec Capture Tool : page sans données perso, gris, 300 dpi, recto.
   - 1d. Analyseur de captures fait main (pcap, en-tête USBPcap, CBW/CSW, opcodes SCSI, n° de trame).
2. Passage sous WinUSB et premier programme C : descripteurs lus par transferts de contrôle (USB 2.0 §9.4.3), Get Max LUN (BOT §3.2), INQUIRY encapsulé à la main, trace de chaque transfert.
3. Rejouer la séquence de scan capturée : une page gris 300 dpi en image brute, puis PGM/PNG.
4. Couleur et recto-verso.
5. Préparation noyau (accord écrit de David) : VM avec passage USB, WinDbg, test-signing, point de restauration.
6. Pilote KMDF : configuration, pipes bulk, URB, interface IOCTL vers un petit outil utilisateur, traces WPP.
7. Outil final et retrait du logiciel Brother (feu vert de David).

Accès au PC : session Remote Control sur « Medabot (claude-chrome) », dépôt dans `C:\Users\morva\claude-chrome\ds720d-scan`.
