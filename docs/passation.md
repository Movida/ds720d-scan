# Passation (24/10/2026)

Repris du projet Claude « Personnel ». Plan détaillé : [Pilote maison du scanner DS-720D](https://claude.ai/artifact/TZYjntxdcNmkXe43hS9rGw).

## Ce qui existe

| Travail | Apport | Limite |
| --- | --- | --- |
| `libsane-dsseries` 1.0.5 (Brother, Linux) | Couvre DS-620/720D/820W/920DW ; prouve qu'un pilote en espace utilisateur suffit | Binaire fermé |
| Retours Linux du DS-620 ([Arch](https://bbs.archlinux.org/viewtopic.php?id=250065)) | Le DS-620 s'annonce en USB Mass Storage ; le pilote Brother lui parle par `/dev/sg` (SCSI brut) | — |
| Backend SANE `avision` (GPL, [source](https://gitlab.com/sane-project/backends/-/raw/master/backend/avision.c)) | Jeu de commandes SCSI Avision (OEM de Brother) ; Brother PDS-6000F ajouté en 03/2026 | Pas le DS-720D |

Aucun pilote libre du DS-720D n'a été trouvé.

## Reconnaissance sur Medabot (24/10, lecture seule)

| Élément | Valeur |
| --- | --- |
| USB | `VID_04F9&PID_60E2`, rév. 0100, classe 08/06/50 (Mass Storage, Bulk-Only, SCSI transparent) |
| Pilotes liés | `USBSTOR` (usbstor.inf) puis `disk` (disk.inf) ; aucun pilote Brother/NovaTek |
| INQUIRY | Vendeur « Brother », produit « DS-720D », révision « 0.27 » |
| Disque | `\\.\PhysicalDrive3`, 1 048 576 o, MBR, une partition FAT12 vide montée en **F:** |
| Logiciel Brother | `NvUSBScan.dll` 12.1.13.28 « NovaTek Msdc Ext » (System32 + SysWOW64) ; TWAIN `twain_32\Brother\DS-720D\DS-720D.ds` et `twain_64\…` ; service `Mobile_Series` actif |

## Voie retenue

Parler au scanner depuis l'espace utilisateur avec les pilotes Microsoft déjà présents : `DeviceIoControl(IOCTL_SCSI_PASS_THROUGH_DIRECT)` sur `\\.\PhysicalDriveN` (droits admin requis). Rien à installer côté pilote, Secure Boot intact. Repli : WinUSB + libusb, seulement avec l'accord de David.

Inconnue principale : le logiciel envoie-t-il des **commandes SCSI propriétaires** (style Avision : SET WINDOW 0x24, READ 0x28…) ou **lit-il et écrit-il des secteurs précis** du faux disque (méthode « MSDC » courante chez NovaTek) ? La capture de l'étape 3 tranche.

Cadre légal : l'art. L122-6-1 IV du CPI autorise l'étude d'un logiciel pour l'interopérabilité.

## Plan

0. ✓ Reconnaissance (ci-dessus).
1. Premier `INQUIRY` en Python `ctypes` par SCSI pass-through.
2. Étude du backend SANE avision.
3. Capture d'une numérisation faite avec le logiciel Brother (USBPcap + Wireshark), décodage SCSI.
4. Prototype : une page, gris, 300 dpi → PNG ; puis couleur et recto-verso.
5. Outil : `ds720d scan --duplex --pdf`, gestion propre des droits admin.
6. Retrait du logiciel Brother (feu vert de David).

## En attente au 24/10

David installe lui-même (le mode auto de Claude Code bloque winget) puis redémarre :

```
winget install --id desowin.USBPcap -e --accept-package-agreements --accept-source-agreements
winget install --id WiresharkFoundation.Wireshark -e --accept-package-agreements --accept-source-agreements
winget install --id Python.Python.3.14 -e --scope user --accept-package-agreements --accept-source-agreements
```

Ensuite : vérifier les versions et les chemins de `USBPcapCMD.exe` et `tshark.exe`, puis capturer.

Accès au PC : session Remote Control sur « Medabot (claude-chrome) », dossier `C:\Users\morva\claude-chrome`.
