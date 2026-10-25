# Passation (mise à jour le 25/10/2026, fin de l'étape 3)

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
| Chaîne C | Build Tools Visual Studio 2022 (17.14), compilateur C x64 et Windows SDK 10.0.26100 ; `construire.cmd` les trouve par vswhere. WDK à installer par David avant l'étape 6 |
| Pilote du scanner | **WinUSB** depuis l'étape 2 (classe USBDevice, nom « DS-720D »), posé par `out\bascule_winusb.exe --oui` ; F: et le logiciel Brother ne le voient plus. Retour à USBSTOR : [winusb.md](winusb.md) |
| Programmes | `out\ds720d.exe` (`descripteurs`, `lun`, `inquiry`, `etat`, `papier`, `scan --sortie FICHIER.brut`), `out\convertir.exe` (brut vers PGM ou PNG, page rendue comme par le pilote Brother ou `--brut`) |
| Câble | Faux contacts possibles pendant un scan (25/10, capture `3e-scan`) : le scanner quitte le bus. Vérifier le câble avant de soupçonner le code |

## Voie retenue

1. **Écouter** le logiciel Brother (USBPcap) pour obtenir la séquence de référence.
2. **Rejouer** en C depuis l'espace utilisateur sur WinUSB, en construisant nous-mêmes les CBW (BOT §5.1), en lisant les CSW (BOT §5.2) et les données par transferts bulk.
3. **Descendre** dans un pilote KMDF qui fait la même chose avec des URB, une fois le protocole maîtrisé.

Pourquoi pas le SCSI pass-through sur USBSTOR (voie du 24/10) : `IOCTL_SCSI_PASS_THROUGH_DIRECT` laisse Windows construire les CBW et gérer le transport, on ne voit ni les endpoints ni les transferts bulk. Contraire à l'objectif « le plus bas possible ».

Inconnue tranchée par la capture 1c : le logiciel n'écrit aucun secteur du faux disque, il emploie deux **commandes SCSI vendeur**, 0xC5 et 0xC3. L'étape 3 les a déchiffrées : 0xC5 est un tunnel vers les commandes de scanner de SCSI-2 (SET WINDOW, SCAN, READ…), 0xC3 lit les blocs d'image. Détail dans [protocole.md](protocole.md).

Cadre légal : l'art. L122-6-1 IV du CPI autorise l'étude d'un logiciel pour l'interopérabilité.

## Feuille de route

0. ✓ Reconnaissance (ci-dessus).
1. ✓ Captures de référence (25/10) ; notre code n'a rien envoyé au scanner, seul le logiciel Brother lui a parlé :
   - 1a. Docs alignées sur la cible KMDF.
   - 1b. Capture de l'énumération (débrancher, rebrancher).
   - 1c. Capture d'un scan avec Capture Tool (tronquée, remplacée par 1e).
   - 1d. Analyseur de captures fait main, contre-vérifié par tshark.
   - 1e. Captures pilotées par Claude (tâche planifiée, client TWAIN) : gris, couleur, noir et blanc 300 dpi, gris 600 dpi, recto-verso, « pas de papier ».
2. ✓ Passage sous WinUSB et premier programme C (25/10) :
   - 2a. Dernière capture de référence, sans Button Manager : la séquence de scan seule.
   - 2b. Chaîne MSVC, trace en C au format commun, comparateur de traces.
   - 2c. Bascule sous WinUSB par `bascule_winusb.exe` (le Gestionnaire de périphériques refuse, classe différente), retour par `pnputil` éprouvé.
   - 2d. Descripteurs lus par transferts de contrôle faits main (USB 2.0 §9.4.3).
   - 2e. GET_MAX_LUN (BOT §3.2) : un seul LUN.
   - 2f. INQUIRY dans un CBW écrit octet par octet (BOT §5), CSW contrôlé (BOT §6.3).
3. ✓ Premier scan depuis notre code (25/10), en rejouant `2a-gris-300-recto-sans-bm` :
   - 3a. Tunnel 0xC5 décodé dans l'analyseur ; [protocole.md](protocole.md).
   - 3b. Image brute reconstituée hors ligne : lignes de 3 plans de 2 592 points, rouge, vert, bleu ; le scanner scanne toujours en couleur.
   - 3c. Lectures par le tunnel sur le scanner ; reprise sur erreur Bulk-Only (BOT §5.3.4).
   - 3d. Commandes de lecture déposées dans le tunnel : présence du papier (0x08).
   - 3e. Scan complet d'une page (accord écrit de David pour les trois SEND vendeur) : même suite de commandes que 2a.
   - 3f. PGM et PNG écrits à la main (blocs deflate stockés, CRC-32 et Adler-32 faits main).
4. Au-delà de la page gris 300 dpi, sur le même protocole : rendu (courbe de tons du pilote Brother, recadrage), recto-verso (fenêtre et READ différents dans `1e-gris-300-recto-verso`), 600 dpi (seule la résolution Y double). La couleur est déjà là. Comprendre les SEND 0x83, 0x95, 0x96 avant d'en changer une valeur.
5. Préparation noyau (accord écrit de David) : VM avec passage USB, WinDbg, test-signing, point de restauration.
6. Pilote KMDF : configuration, pipes bulk, URB, interface IOCTL vers un petit outil utilisateur, traces WPP.
7. Outil final et retrait du logiciel Brother (feu vert de David).

Accès au PC : session Remote Control sur « Medabot (claude-chrome) », dépôt dans `C:\Users\morva\claude-chrome\ds720d-scan`.
