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

### 6c : traces WPP et enregistreur IFR (25/10)

Fichiers :
- `noyau/wpp.h` : fournisseur WPP du pilote (GUID `{69D7FAD8-DB14-46C0-AD2F-35EE5136C07E}`), un drapeau par couche (`TRACE_PILOTE`, `TRACE_PNP`, puis `TRACE_USB`, `TRACE_BOT`, `TRACE_IOCTL`), fonction `Trace(NIVEAU, DRAPEAU, MSG, ...)` ; `WPP_DEBUG` recopie chaque message retenu vers le débogueur par `DbgPrintEx`.
- `noyau/ds720d.c` : `WPP_INIT_TRACING` en tête de `DriverEntry`, `WPP_CLEANUP` au déchargement (ou si `WdfDriverCreate` échoue), `Trace` à la place de `DbgPrintEx`.
- `Makefile` : `tracewpp -km -I…\WppConfig\Rev1 -scan:noyau\wpp.h -p:ds720d -odir:out\noyau` écrit `out\noyau\ds720d.tmh` ; `ENABLE_WPP_RECORDER=1` et `wpprecorder.lib` pour l'IFR, comme le projet MSBuild du WDK ; `WINNT=1` et `DEPRECATE_DDK_FUNCTIONS=1`, posés par le WDK pour tout pilote.
- `noyau/ds720d.inf` : version 6.3.0.0. `installer.ps1 installer` installe une nouvelle version par-dessus l'ancienne (Windows préfère la plus haute), puis retire l'ancienne du magasin.

Vérifié dans la VM (instantané `avant-6c`) :
1. Mise à jour de 6.2 vers 6.3 (`oem11.inf`, l'ancien `oem10.inf` retiré) ; mêmes rappels qu'en 6b, recopiés en direct dans le journal de WinDbg.
2. `!rcdrkd.rcdrlogdump ds720d` (après `.sympath+ …\out\noyau` et `.reload /f ds720d.sys`) : les cinq messages du tampon IFR, décodés à partir du PDB, avec le nom de la fonction émettrice.
3. Vidage du noyau pris en direct dans la VM (Gestionnaire des tâches, Détails, clic droit sur System, vidage complet de la mémoire du noyau : 655 Mo, sans plantage), rapatrié par `invite.ps1`, lu sur Medabot par `kd.exe` du WDK (accord A4) : les mêmes cinq messages par `!rcdrkd.rcdrlogdump ds720d`, et le journal interne de KMDF par `!wdfkd.wdflogdump ds720d -f` (machine d'états PnP et alimentation, `IRP_MN_START_DEVICE`, passage en D0).

Lire les traces :
- En direct : le journal de WinDbg (`ds720d : …`), ou, VM arrêtée par Break, `!rcdrkd.rcdrlogdump ds720d` et `!wdfkd.wdflogdump ds720d -f`.
- Après un plantage ou sur un vidage : `kd.exe -z VIDAGE -y "srv*C:\ProgramData\Dbg\sym*https://msdl.microsoft.com/download/symbols;C:\Users\morva\claude-chrome\ds720d-scan\out\noyau" -logo JOURNAL -c "!rcdrkd.rcdrlogdump ds720d; !wdfkd.wdflogdump ds720d -f; q"`. Le PDB doit être celui du `.sys` chargé : reconstruire change son identifiant.
- Un vidage du noyau de la VM peut contenir la clé KDNET, gardée en mémoire par le noyau : il reste hors du dépôt et hors du fil, et s'efface après l'analyse (fait pour celui de 6c, dans la VM et sur Medabot ; seul le journal de `kd`, sans la clé, est gardé dans `ds720d-captures\vidages`).

Pièges :
- Sans `WINNT=1`, `evntrace.h` ne déclare rien en mode noyau (son contenu est sous `#if defined(_WINNT_) || defined(WINNT)`) : `TRACE_LEVEL_*` inconnus. Le projet MSBuild du WDK le définit pour tout pilote, notre `Makefile` ne le faisait pas.
- Avec `/std:c17`, `cl` emploie le préprocesseur conforme : `MSG "\n", __VA_ARGS__` garde la virgule finale quand un message n'a pas d'argument. `, ## __VA_ARGS__` la retire.
- `tracewpp` lit un source sans BOM dans la page de code de Windows : nos accents de commentaires y sont mal lus, sans effet ; les messages restent en ASCII.
- `!wdfkd.wdflogdump ds720d` seul ne fait que proposer `-d` ou `-f` : le journal de KMDF se demande par `-f`.

### 6d : premiers URB, sur le pipe de contrôle (25/10)

Fichiers :
- `noyau/usb.c`, `noyau/usb.h` : couche URB générique. Inscription auprès de la pile (`USBD_CreateHandle`, contrat 0x602) ; URB alloués par `USBD_UrbAllocate` ; envoi par une requête KMDF préparée à la main (`WdfIoTargetFormatRequestForInternalIoctlOthers`, puis `USBD_AssignUrbToIoStackLocation` dans l'emplacement de pile suivant, envoi synchrone avec délai de 5 s). `UsbControle` remplit un `URB_FUNCTION_CONTROL_TRANSFER_EX` champ par champ avec les 8 octets SETUP de l'appelant (délai de 2 s dans l'URB) ; `UsbChercherInterface` parcourt les descripteurs comme `src/ds720d.c` ; `UsbChoisirConfiguration` envoie l'URB `SELECT_CONFIGURATION` (construit par `USBD_SelectConfigUrbAllocateAndBuild`, l'allocateur qui va avec l'inscription) et lit les poignées de pipes dans sa réponse ; `UsbAbandonner` envoie `ABORT_PIPE`.
- `noyau/bot.c`, `noyau/bot.h` : couche Bulk-Only, pour l'instant GET_MAX_LUN (BOT §3.2).
- `noyau/ds720d.c` : contexte de l'appareil ; au démarrage (`EvtDevicePrepareHardware`), descripteurs DEVICE et CONFIGURATION avec les paquets SETUP de 1b, contrôle des identifiants, interface 08/06/50, sélection de la configuration, GET_MAX_LUN ; au retrait, abandon des pipes et désinscription. Copie des traces vers WinDbg facultative (valeur `EchoDebogueur`, voir plus bas).
- `noyau/installer.ps1` : action `echo 0|1`. INF en version 6.4.1.

Vérifié dans la VM (instantané `avant-6d-bis`) :
1. Démarrage (`!rcdrkd` et journal de WinDbg) : DEVICE 18 o, CONFIGURATION 9 puis 32 o, `SELECT_CONFIGURATION` réussi, pipes bulk IN 0x81 et OUT 0x02 de 512 o, GET_MAX_LUN rend 0 ; statut USBD 0 partout.
2. Sur le bus (capture `6d-demarrage-2`, [captures.md](captures.md)) : la séquence du pilote est **identique à celle de Windows dans 1b** (trames 19191 à 19224, 16 lignes, `compare_traces.py`), aux lectures STRING et au SET_INTERFACE près, que notre pilote n'envoie pas. Le concentrateur relit de son côté DEVICE (64 puis 18 o) à chaque énumération.
3. Endurance : 40 cycles désactiver-réactiver sans débogueur, 41 démarrages complets dans la capture, aucune faute ; Driver Verifier : aucune allocation restante au déchargement (3 au plus fort).
4. Contre-épreuve avec la 6.4.1 (copie vers WinDbg coupée) : mise à jour depuis la 6.4, puis 40 cycles **WinDbg attaché**, aucune faute (41 chargements et déchargements notés par Driver Verifier dans le journal de WinDbg, VM jamais redémarrée).

Deux plantages, et ce qu'ils ont appris :
- Les deux sont des **0x80 NMI_HARDWARE_FAILURE** (« TDO »), processeur au repos ou dans la DPC du disque NVMe de la VM, aucune ligne de notre code sur la pile, juste après une rafale de messages recopiés vers WinDbg (KDNET).
- Le premier, à 19:44, avait en plus une cause de banc : Windows dans la VM s'est mis en veille (S1, 15 minutes d'inactivité sur secteur) ; VMware traite cette veille en suspendant la VM, ce qui rend le scanner à Medabot, puis la VM a repris. Veille coupée ensuite (`powercfg /change standby-timeout-ac 0`, l'hibernation l'était déjà).
- Le second, au 8e cycle, WinDbg attaché, sans veille : même NMI. Sans débogueur, 40 cycles sans faute. Hypothèse retenue (déduite, pas prouvée) : avec KDNET, chaque DbgPrint gèle les processeurs de la VM le temps de l'envoi, et une rafale finit par provoquer une NMI que Windows prend pour une panne. Décision : la copie des traces vers WinDbg est coupée par défaut (`installer.ps1 echo 1` la rétablit pour une séance) ; les traces restent toujours dans l'IFR (`!rcdrkd.rcdrlogdump ds720d`, ou `kd.exe` sur un vidage).
- Les vidages ont été analysés par `kd.exe` (accord A4) puis effacés ; la VM a été arrêtée dans WinDbg chaque fois, puis relancée par `g` (vidage écrit, redémarrage).

Pièges :
- `IOCTL_INTERNAL_USB_SUBMIT_URB` est dans `usbioctl.h`, pas dans `usb.h`.
- Ne jamais suspendre la VM (bouton de VMware ou veille de Windows) pendant que le scanner lui est passé : VMware le rend à Medabot, et la reprise d'une VM attachée à KDNET a précédé une NMI.
- Un PowerShell admin ouvert après un redémarrage de la VM part de `C:\WINDOWS\system32` : se placer d'abord dans `C:\Users\Public\ds720d`.

### 6e : interface IOCTL, Bulk-Only dans le noyau, barrière, ds720dk.exe (25/10)

Fichiers :
- `src/permis.c`, `src/permis.h` : la barrière, en C pur, compilée pour l'outil et pour le pilote. Les tables de lectures et de dépôts 0xC5 sortent de `tunnel.c` sans changer un octet (474 nombres comparés à l'ancienne version) ; s'y ajoutent les 6 paquets SETUP de 1b, INQUIRY (le CDB de 1b, 36 o), la forme des CDB 0xC5 et 0xC3 (longueur du CDB égale à celle du CBW, octets réservés nuls), 0xC3 en lecture de 1 à 65 536 o. `tunnel.c` s'en sert ; le pilote aussi.
- `src/essai_permis.c` : 115 cas hors ligne ; chaque requête observée passe, chaque variante (un octet de dépôt, un sens, une longueur, TEST UNIT READY, WRITE(10), FORMAT UNIT, WRITE BUFFER, STRING du numéro de série…) est refusée.
- `noyau/ds720d_ioctl.h` : interface partagée : GUID de l'interface de périphérique, `IOCTL_DS720D_CONTROLE` (un paquet SETUP de 1b) et `IOCTL_DS720D_BOT` (une commande Bulk-Only), en `METHOD_BUFFERED` ; la sortie de `BOT` rend l'étape atteinte, le statut, le résidu, et les octets du CBW et du CSW.
- `noyau/usb.c` : `UsbBulk` (`URB_FUNCTION_BULK_OR_INTERRUPT_TRANSFER`) et `UsbDebloquer` (`SYNC_RESET_PIPE_AND_CLEAR_STALL`).
- `noyau/bot.c` : `BotCommande` (CBW octet par octet, données, CSW contrôlé selon BOT §6.3) et `BotReprise` (Reset Recovery, BOT §5.3.4), repris de `src/bot.c`.
- `noyau/ioctl.c` : interface de périphérique, file unique séquentielle au niveau PASSIVE, barrière avant tout envoi (refus : `STATUS_ACCESS_DENIED`, rien sur le bus).
- `noyau/ds720d.c` : ouverture exclusive, `FILE_DEVICE_SECURE_OPEN` ; INF : sécurité de l'appareil en SDDL (Système et Administrateurs tout, Utilisateurs lecture-écriture), version 6.5.
- `src/client_noyau.c` : le transport de `ds720dk.exe` par les deux IOCTL ; `ds720dk.exe` = `ds720d.c`, `tunnel.c`, `trace.c` tels quels, liés à ce fichier au lieu de `peripherique.c` et `bot.c`.
- `src/essai_refus.c` : deux requêtes inoffensives absentes de la liste (TEST UNIT READY, descripteur STRING 2), envoyées au vrai pilote.

Vérifié dans la VM (instantané `avant-6e`, capture `6e-inquiry`), l'outil lancé sans élévation :
1. `ds720dk descripteurs`, `lun` et `inquiry` réussis (« Brother », « DS-720D », « 0.27 », CSW statut 0).
2. Traces de `ds720dk.exe` **identiques** à celles de `ds720d.exe` sous WinUSB en 5d (18 et 25 lignes, tags mis à part), et à la capture de notre passage (18, 21 et 25 lignes, **tags compris** : le pilote rend le CBW qu'il a réellement envoyé).
3. `essai_refus.exe` : TEST UNIT READY et STRING 2 refusés (`ERROR_ACCESS_DENIED`) ; la capture ne montre rien après l'INQUIRY : le pilote les a arrêtés avant tout envoi.

Pièges :
- `CTL_CODE` décale le type d'appareil de 16 bits : 0x8720 en `int` déborde (C4245 sous `/W4 /WX`) ; type écrit `0x8720u`.
- En `METHOD_BUFFERED`, entrée et sortie partagent le même tampon système : le pilote recopie l'en-tête d'entrée avant tout, et n'écrit l'en-tête de sortie qu'après le transport, pour ne pas écraser des données sortantes encore à envoyer.
- Une requête qui finit en erreur n'est pas recopiée vers l'outil par le gestionnaire d'E/S : `IOCTL_DS720D_BOT` réussit dès que le pilote l'a traitée, l'échec du transport est dans la sortie ; seul un refus de la barrière ou une requête mal formée la fait échouer.
- Heredoc de Git Bash et barres obliques inverses : un script Python passé par heredoc a perdu ses `\` (`\b`, `\e`) ; le `Makefile` se modifie par l'outil d'édition.

### 6f : le tunnel 0xC5 par le pilote (25/10)

Aucun code nouveau : `ds720d.c` et `tunnel.c` passent déjà par `client_noyau.c`, et la barrière du pilote connaît les lectures et dépôts 0xC5 observés (6e). Vérifié dans la VM, sans élévation (capture `6f-tunnel`) :
1. `ds720dk etat` (prise de contact du logiciel Brother : signature « NOVA », sondages, identifiants) : réussi ; 26 commandes, identiques à celles de `ds720d.exe` sous WinUSB en 5d.
2. `ds720dk papier` sans feuille : « pas de feuille » ; 53 commandes, identiques à celles de 3d (`3d-trace-sans-2`), dont le dépôt de 0x08.
3. `ds720dk papier` avec une feuille engagée : « feuille engagée », feuille non entraînée ; 187 commandes, identiques à celles de 3d (`3d-trace-avec`), dont six dépôts (0x08 et READ 0xA0).
4. Capture contre traces de `ds720dk.exe` : concordance parfaite, tags compris (105, 212 et 742 lignes, les mêmes nombres qu'en 3c et 3d). Contre les traces de WinUSB, seules diffèrent quelques réponses de sondage (`ff 03`, `ff 05`, octet 8), qui varient d'un passage à l'autre (docs/protocole.md §2) : les commandes ont été comparées seules, réponses écartées.

### 6g : scan par le pilote (25/10)

Aucun code nouveau dans le pilote ni dans l'outil : `ds720d.c` (boucle de lecture) et `tunnel.c` passent par `client_noyau.c`, la barrière connaît les dépôts du scan (accordés aux étapes 3 et 4) et les lectures 0xC3. Seul le banc change (ci-dessous). Vérifié dans la VM, sans élévation :
1. **Recto 300 dpi** (`6g-recto`) : 16 blocs, 1 280 lignes, 6,4 s.
2. **Recto-verso de deux feuilles** (`6g-rv`) : 188 blocs, quatre faces de 3 760 lignes, 38 s attente de la seconde feuille comprise.
3. **600 dpi** (`6g-600`) : 89 blocs, 7 120 lignes, 21 s. Un premier essai s'était arrêté sur « pas de feuille » (feuille pas assez engagée) : rien n'a été scanné.
Pour chacun : trace de `ds720dk.exe` identique à la capture recollée (21 994, 53 374 et 70 765 lignes, tags compris) ; `verif_blocs.py` : 0 écart ; brut identique, octet pour octet, aux blocs ou aux faces extraits de la capture ; suite des dépôts identique à celle des scans de `ds720d.exe` sous WinUSB (3g, 4e, 4f), répétitions de READ image repliées.

Débit des lectures 0xC3, mesuré sur les captures : 26,3 Mo/s par notre pilote dans la VM (2,44 ms par lecture de 64 Kio en médiane), contre 29,0 Mo/s par WinUSB sur Medabot (2,24 ms, capture 3g). La durée d'un scan reste celle de la mécanique, environ 0,39 s par bloc dans les deux cas. `METHOD_BUFFERED` est donc gardé : la copie du tampon système ne se voit pas (§ 2).

**Ce que VMware fait de nos lectures** (réserve de 5d levée) : notre pilote envoie un seul URB de 64 Kio, mais l'hôte le découpe en deux (36 864 + 28 672 o) ; USBPcap, sur Medabot, voit les deux morceaux. Le banc en tient compte :
- `banc/analyse_capture.py --recoller` rassemble les données entrantes d'une même commande en une seule ligne DATA-IN, comme les voit le pilote ; sans effet sur les captures de Medabot (2a et 3g : sortie identique avec et sans l'option ; `contre_verif.py` sur 2a : 0 écart).
- `banc/extrait_image.py` suit une lecture 0xC3 arrivée en plusieurs morceaux (toujours, sans option).

Piège : les traces de `ds720dk.exe` ne mesurent pas la durée d'une commande (CBW, données et CSW y sont écrits au retour de l'IOCTL) ; le débit se mesure sur la capture.
