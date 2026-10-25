# Le pilote KMDF du DS-720D (étape 6)

Plan relu par David le 25/10/2026 : « Ok pour tout cela », qui vaut « go » sur les sous-étapes 6a à 6i et accord écrit pour A1 à A4 (section 4). Règles dans [CLAUDE.md](../CLAUDE.md), banc dans [noyau.md](noyau.md), protocole dans [protocole.md](protocole.md).

Point de départ : étape 5 close (tag `etape-5`), VM `DS720D-NOYAU` avec test-signing et KDNET (instantané `test-signing-pret`), scanner sous WinUSB, WDK 10.0.26100 complet (Inf2Cat, InfVerif, tracewpp, WppRecorder, usbdex, kd.exe). **Le pilote ne se charge que dans la VM.**

## 1. Partage du travail entre noyau et outil

```
VM DS720D-NOYAU
  ds720dk.exe (sans élévation)
    ds720d.c + tunnel.c  : chorégraphie du scanner, inchangée
    trace.c              : trace au format commun, inchangée
    client_noyau.c       : remplace peripherique.c et bot.c, parle au pilote
          │ DeviceIoControl
  ds720d.sys (KMDF)
    barrière             : seules passent les commandes observées
    Bulk-Only            : CBW, CSW, tags, Reset Recovery
    URB faits main       : contrôle, configuration, bulk, déblocage
          │ IOCTL_INTERNAL_USB_SUBMIT_URB
  pile USB de Windows → xHCI virtuel → VMware → scanner   (USBPcap de Medabot voit tout)
```

Le pilote fait ce que fait USBSTOR (le transport Bulk-Only, en URB) et y ajoute la barrière des commandes observées ; l'outil garde le protocole du scanner, comme Brother le fait avec `NvUSBScan.dll` en espace utilisateur au-dessus d'USBSTOR.

- Pourquoi pas un pilote mince qui relaierait des transferts bulk : ce serait un clone de WinUSB, et le transport Bulk-Only, le cœur de ce qu'on veut descendre, resterait en espace utilisateur.
- Pourquoi pas tout le scan dans le noyau : des attentes de plusieurs secondes, l'écriture de fichiers et le Ctrl+C n'y ont pas leur place, et chaque bug y devient un écran bleu.
- Conséquence voulue : `ds720d.c` et `tunnel.c` ne changent pas, seule l'édition de liens change (comme `essai_bot.exe` et ses bouchons). Les traces de `ds720d.exe` (WinUSB) et de `ds720dk.exe` (notre pilote) doivent être **identiques ligne à ligne**, tags mis à part (`compare_traces.py --sans-tags`).

## 2. Choix techniques

| Sujet | Retenu | Écarté, et pourquoi |
| --- | --- | --- |
| Accès USB | URB remplis champ par champ, envoyés par `IOCTL_INTERNAL_USB_SUBMIT_URB` à la cible d'E/S de KMDF ; notre propre URB `SELECT_CONFIGURATION`, poignées de pipes lues dans sa réponse ; enregistrement auprès de la pile par `USBD_CreateHandle` | Objets `WDFUSBDEVICE`/`WDFUSBPIPE` : voie recommandée par Microsoft pour un pilote de production, plus courte, mais KMDF y choisit la configuration et construit les URB à notre place. KMDF garde ce qui n'est pas de l'USB : PnP, alimentation, files d'E/S |
| Transferts de contrôle | `URB_FUNCTION_CONTROL_TRANSFER_EX`, les 8 octets SETUP posés à la main (les mêmes qu'en espace utilisateur), délai par URB | `URB_FUNCTION_GET_DESCRIPTOR_FROM_DEVICE` : la pile écrirait le paquet SETUP elle-même |
| Exécution | File séquentielle au niveau PASSIVE, envois synchrones, délai de 5 s par URB (comme `DELAI_BULK_MS`) | Chaîne asynchrone de routines d'achèvement : plus rapide, mais une machine d'états difficile à suivre, pour un protocole qui ne traite qu'une commande à la fois (BOT §5) |
| Interface avec l'outil | Deux IOCTL `METHOD_BUFFERED` : `CONTROLE` (un paquet SETUP) et `BOT` (CDB, sens, longueur, données ; rend statut, résidu, octets reçus, et les octets du CBW et du CSW pour la trace). Le tampon système, non paginé, va tel quel dans l'URB | `METHOD_OUT_DIRECT` (MDL de l'appelant dans l'URB, zéro copie) : la copie de 64 Kio coûte quelques microsecondes ; mesure en 6g |
| Barrière | Le pilote refuse tout ce qui n'est pas observé : les 6 paquets SETUP de 1b (descripteurs DEVICE, CONFIGURATION, STRING 0, GET_MAX_LUN), INQUIRY, les lectures 0xC5 de `tunnel.c`, les dépôts identiques à l'octet près, 0xC3 en lecture de 64 Kio au plus. Tables sorties de `tunnel.c` vers un module commun, en C pur, testé hors ligne (`essai_permis.exe`) avant tout chargement | Barrière dans l'outil seul : un autre programme ou un bug de l'outil la contournerait. Le pilote est le seul passage obligé |
| Accès à l'appareil | Interface de périphérique à GUID propre, ouverture exclusive (deux clients entrelaceraient leurs CBW), `FILE_DEVICE_SECURE_OPEN`, sécurité posée par l'INF : système et administrateurs, lecture-écriture pour l'utilisateur interactif (l'outil tourne sans élévation, comme sous WinUSB) | Administrateurs seuls : chaque essai demanderait l'élévation de David dans la VM |
| Installation | INF écrite à la main : classe USBDevice (celle de WinUSB), identifiant matériel exact `USB\VID_04F9&PID_60E2`, KMDF 1.15 sans coinstallateur ; catalogue par Inf2Cat, signé par `signer.ps1` ; installée par `pnputil` | devcon (un outil de plus à exécuter), Zadig (exclu par le projet) |
| Traces du pilote | `DbgPrintEx` en 6b, puis WPP avec l'enregistreur en mémoire (IFR) : lisible en direct dans WinDbg (`!rcdrkd.rcdrlogdump`) et dans un vidage après plantage, sans rien installer dans la VM. La trace au format commun reste écrite par l'outil ; USBPcap de Medabot reste le témoin indépendant | Session ETW dans la VM (`tracelog`) : un binaire de plus à y copier et lancer |
| Filets en développement | Driver Verifier (options standard) et vérificateur KMDF sur `ds720d.sys`, dans la VM : erreurs d'IRQL, de mémoire ou fuites deviennent un arrêt immédiat, lisible dans WinDbg | Les découvrir plus tard, au hasard |
| Cible | KMDF 1.15 (comme `bonjour.sys`), `NTDDI_VERSION` Windows 10 2004 (`ExAllocatePool2`) | |

Pas de déconfiguration au retrait (`SET_CONFIGURATION 0`) : documentée (USB 2.0 §9.4.7) mais jamais observée, ni USBSTOR ni WinUSB ne l'envoient dans nos captures (5d). Le pilote s'en tient à l'abandon des pipes, côté hôte (`ABORT_PIPE`, vu en 5d).

### Couches, en vue d'autres pilotes

Question de David (25/10) : ce qui pourra servir à d'autres pilotes, à revoir en fin de projet. Les couches restent donc dans des fichiers séparés, aux interfaces étroites, sans cadre générique construit d'avance :

| Couche | Réutilisable pour |
| --- | --- |
| Banc (VM, KDNET, test-signing), cible noyau du `Makefile`, signature, INF et catalogue, installation, USBPcap, analyseur, `compare_traces.py` | tout pilote |
| URB : contrôle, configuration, bulk, déblocage | tout appareil USB |
| Transport Bulk-Only | tout appareil USB Mass Storage |
| Barrière, protocole vendeur (tunnel, scan) | le DS-720D seul |

## 3. Sous-étapes

Chaque sous-étape : un commit, un tag `etape-6x`, vérifiée dans la VM sur le vrai scanner avant la suivante, instantané de la VM avant chaque premier chargement d'une nouvelle version du pilote.

| | Contenu | Vérifié par | Accord |
| --- | --- | --- | --- |
| 6a | Ce document, passation, historique | relecture | non |
| 6b | Squelette PnP sans aucun transfert : `DriverEntry`, `EvtDriverDeviceAdd`, `PrepareHardware`, `ReleaseHardware`, `D0Entry`, `D0Exit`, messages `DbgPrintEx`. INF, catalogue, signature, cibles du `Makefile` ; `noyau/installer.ps1`, qui refuse de tourner si `hostname` ne vaut pas `DS720D-NOYAU`. Retour à WinUSB documenté et rodé | scanner sous `ds720d` sans code de problème ; rappels lus dans WinDbg ; désactiver puis réactiver ; aller-retour WinUSB ; capture : rien de notre fait sur le bus | A1, A2, A3 |
| 6c | Traces WPP et enregistreur IFR à la place de `DbgPrintEx` (`tracewpp` dans le `Makefile`, formats tirés du PDB) | mêmes évènements lus par `!rcdrkd.rcdrlogdump`, en direct et dans un vidage | A4 |
| 6d | Premiers URB, sur le pipe de contrôle, au démarrage : descripteurs DEVICE et CONFIGURATION (1b, trames 19191 à 19199), `SELECT_CONFIGURATION` construit à la main (`SET_CONFIGURATION 1`, trame 19214), GET_MAX_LUN (trame 19223) ; endpoints lus, pas supposés. Abandon des pipes au retrait | capture du démarrage comparée à 1b par `compare_traces.py` ; WPP : endpoints 0x81 et 0x02, LUN max 0 ; vingt cycles désactiver-réactiver sous Driver Verifier sans fuite | non (USB standard, observé) |
| 6e | Interface IOCTL, transport Bulk-Only dans le noyau (CBW, CSW, contrôles de BOT §6.3, Reset Recovery, délais), barrière et `essai_permis.exe` ; `ds720dk.exe` | `essai_permis.exe` hors ligne ; `ds720dk descripteurs`, `lun`, `inquiry` dans la VM : trace identique à celle de `ds720d.exe` en 5d et à la capture de notre passage ; un TEST UNIT READY (vu chez Windows en 5d, inoffensif, absent de la liste) refusé par le pilote, sans aucun trafic dans la capture | non |
| 6f | Tunnel 0xC5 par le pilote : `ds720dk etat`, `papier` avec et sans feuille | traces comparées à 1b (prise de contact) et à nos traces de 3d, capture | non (lectures et dépôts déjà accordés) |
| 6g | Scan par le pilote : recto 300 dpi, recto-verso de deux feuilles, 600 dpi ; débit comparé à WinUSB | brut identique aux blocs recollés de la capture de notre passage ; traces contre capture ; découpage éventuel de nos URB de 64 Kio par VMware (réserve de 5d) | non (dépôts accordés aux étapes 3 et 4) |
| 6h | Robustesse : Ctrl+C pendant un scan ; débranchement pendant une lecture (VMware > Déconnecter, l'équivalent du faux contact du câble) ; désactivation du périphérique pendant une commande ; arrêt brutal de l'outil | ni écran bleu ni fuite sous Driver Verifier ; le scanner repart après rebranchement ; RELEASE UNIT envoyé comme sous WinUSB | non |
| 6i | Relecture de fond, CLAUDE.md, HISTORIQUE.md, passation, tag `etape-6` | relecture indépendante | non |

## 4. Accords écrits de David (25/10/2026)

« Ok pour tout cela », en réponse au plan qui les détaillait :

- **A1** (6b) : importer la partie publique du certificat de test (`ds720d-test.cer`) dans les magasins **Root** et **TrustedPublisher** de l'ordinateur, **dans la VM seulement**, pour que `pnputil` installe un paquet signé en test. Jamais sur Medabot.
- **A2** (6b) : Driver Verifier (`verifier /standard /driver ds720d.sys`, un redémarrage de la VM) et vérificateur KMDF (registre du service `ds720d`), dans la VM.
- **A3** (6b) : premier chargement de `ds720d.sys` dans la VM, où il remplace WinUSB pour le scanner.
- **A4** (6c) : `kd.exe` du WDK (Microsoft, déjà installé) lancé par Claude sur Medabot pour lire, sans la clé KDNET, les vidages mémoire écrits par la VM après un plantage.

Rien d'autre ne change de nature : aucune nouvelle commande SCSI (INQUIRY, 0xC5 observés, dépôts déjà accordés, 0xC3). Les seuls échanges USB nouveaux pour notre code sont standard et observés chez Windows : `SET_CONFIGURATION 1` (1b, trame 19214) et `CLEAR_FEATURE(ENDPOINT_HALT)` d'un déblocage (trame 19241, déjà dans `bot.c`) ; la Reset Recovery reste celle de BOT §5.3.4.

## 5. Déroulé des séances

- Commandes admin dans la VM : par `noyau\installer.ps1`, qui vérifie lui-même `hostname` ; Claude rappelle quand même de le vérifier avant chaque commande.
- WinDbg attaché à chaque séance, journal ouvert par `.logopen /t C:\Users\morva\ds720d-captures\windbg\etape6.log` : Claude lit ce journal (hors du dépôt).
- Windows Update suspendu dans la VM pendant l'étape (Paramètres > Windows Update > Suspendre).
- David passe le scanner à la VM (menu de VMware) et glisse les feuilles ; Claude prend les instantanés par `vmrun` (`avant-6b`, `avant-6d`…).

## 6. Risques et retour arrière

- **Écran bleu au démarrage du pilote** : WinDbg s'arrête dessus. Si la VM replante à chaque démarrage (le scanner rebranché relance le pilote), déconnecter le scanner dans VMware ou revenir à l'instantané précédent.
- **Retour à WinUSB dans la VM** : `pnputil /delete-driver oemNN.inf /uninstall`, puis `bascule_winusb.exe --oui`, comme à l'étape 2 ; ou l'instantané `test-signing-pret`. Rodé dès 6b.
- **Le scanner passe par USBSTOR** entre deux pilotes dans la VM : montage automatique coupé depuis 5d ; Windows y a déjà lu le faux disque sans y écrire.
- **VMware et les gros transferts** : si l'hôte découpe nos URB de 64 Kio, la comparaison des traces avec la capture devra en tenir compte (6g).
- **Medabot** n'installe jamais le paquet : il s'y construit et s'y signe seulement. Installé par erreur, il serait refusé (certificat approuvé nulle part sur Medabot, pas de test-signing possible sous Secure Boot).

## 7. Journal des sous-étapes

### 6b : squelette PnP et installation dans la VM (25/10)

Fichiers :
- `noyau/ds720d.c` : `DriverEntry`, `EvtDriverDeviceAdd`, `PrepareHardware`, `ReleaseHardware`, `D0Entry`, `D0Exit`, `SurpriseRemoval`, `EvtDriverUnload`, chacun annoncé par `DbgPrintEx` ; aucun transfert. Rappels de PnP en section `PAGE`, `DriverEntry` en `INIT`, rappels d'alimentation non paginés (`dumpbin` : sections `PAGE` et `INIT` présentes, imports `ntoskrnl.exe` et `WDFLDR.SYS`).
- `noyau/ds720d.inf` : écrite à la main, en ASCII ; classe USBDevice, identifiant matériel exact, `DefaultDestDir = 13` (le pilote tourne depuis le magasin de pilotes), `PnpLockdown`, KMDF 1.15, vérificateur KMDF posé dans le registre du service (`VerifierOn`, `VerboseOn`). `InfVerif /w` et `/k` : valide.
- `Makefile` : cible `out\noyau\ds720d.sys` ; `NTDDI_VERSION` fixé à Windows 10 2004 pour tous les pilotes du dépôt.
- `noyau/paquet.ps1` : copie dans `out\noyau\paquet`, signature du `.sys`, `InfVerif /w`, `Inf2Cat /os:10_GE_X64`, signature du catalogue, empreintes.
- `noyau/installer.ps1` : actions `etat`, `certificat`, `verificateur`, `verificateur-arret`, `installer`, `cycle`, `retour` ; refuse de tourner ailleurs que sur `DS720D-NOYAU`.

Déroulé dans la VM (instantané `avant-6b` pris avant) :
1. `certificat` (A1), `verificateur` (A2), redémarrage : Driver Verifier actif sur `ds720d.sys` (options 0x1209BB, celles de `/standard`), annoncé par WinDbg au démarrage.
2. Scanner passé à la VM sous WinUSB, puis `installer` (A3) : le scanner passe sous `ds720d` (`oem10.inf`, section `Installer_ds720d.NT`, version 6.2.0.0, code de problème 0). WinDbg : `DriverEntry`, `EvtDriverDeviceAdd`, `EvtDevicePrepareHardware` (0 ressource matérielle, normal pour un appareil USB), `EvtDeviceD0Entry` depuis `D3Final`.
3. `cycle 5` : à chaque désactivation, `D0Exit` vers `D3Final`, `ReleaseHardware`, puis `dechargement` ; à chaque réactivation, `DriverEntry` à nouveau. Sans appareil à tenir, Windows décharge le pilote : c'est le fonctionnement normal d'un pilote PnP à démarrage à la demande. Aucune faute sous Driver Verifier ni sous le vérificateur KMDF.
4. `retour` : USBSTOR un instant (lectures seules, aucun volume monté), puis WinUSB ; `ds720d inquiry` dans la VM : trace identique à celle de 5d.
5. `installer` à nouveau : le scanner reste sous `ds720d` pour la suite.

Contrôle sur le bus (capture `6b-installation`, [captures.md](captures.md)) : pendant que `ds720d` tient le scanner, seul le concentrateur lui parle (descripteur DEVICE à chaque énumération) ; aucun SET_CONFIGURATION, aucun CBW de notre fait.

Pièges :
- `Import-Certificate` a refusé le magasin TrustedPublisher de l'ordinateur (E_ACCESSDENIED, en administrateur), qui n'existait pas encore dans la VM ; Root est passé. Cause probable : le fournisseur `Cert:` de PowerShell 5.1 n'ouvre qu'un magasin existant. `installer.ps1` passe désormais par la classe `X509Store` de .NET, qui le crée.
- `pnputil /remove-device` (et `/disable-device`, `/enable-device`) affiche l'identifiant d'instance du scanner, numéro de série compris : vu sur une capture d'écran du premier essai, restée dans le fil du projet. `installer.ps1` filtre désormais la sortie de `pnputil`.
- Windows Update a redémarré la VM pendant la séance (mise à jour déjà en cours) ; suspendu ensuite jusqu'au 29/11.
- `.logopen` est une commande de WinDbg, à taper dans sa fenêtre Command (VM arrêtée par Break, puis `g`), pas dans PowerShell.
