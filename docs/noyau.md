# Banc noyau : VM, passage USB, débogage, test-signing

Préparé à l'étape 5 (25/10/2026) pour l'étape 6 (pilote KMDF). Règles dans [CLAUDE.md](../CLAUDE.md) ; tout ce qui touche au noyau, à bcdedit, à Secure Boot ou à la signature des pilotes demande l'accord écrit de David.

## Principe

Le pilote ne se charge **que dans une machine virtuelle** Windows, jamais sur Medabot. Le scanner est passé à la VM par USB, le débogueur noyau tourne sur Medabot et se relie à la VM par le réseau virtuel.

```
Medabot (hôte, intact)                       VM Windows 11 (invité, jetable)
  WinDbg  ◄──── KDNET (UDP, réseau hôte-VM) ────  noyau en mode débogage
  WDK + nmake : construit et signe le pilote ──►  test-signing, Secure Boot coupé
  VMware : arbitrage USB  ──── scanner DS-720D ──►  xHCI virtuel ─► notre pilote KMDF
```

Sur Medabot, **ni bcdedit, ni Secure Boot, ni VBS/HVCI ne changent**. Avec Secure Boot actif, `bcdedit /set testsigning on` y est d'ailleurs refusé (constaté par erreur en 5f) : un pilote signé en test ne peut pas s'y charger. Un écran bleu tue la VM, pas le PC ; un instantané de la VM la remet en état.

Pourquoi pas sur Medabot : il faudrait couper Secure Boot et HVCI sur le PC principal (sauvegardes, WSL, Docker), et le débogage noyau exige de toute façon une seconde machine.

## Inventaire de départ (25/10, lecture seule, sans élévation)

| Élément | Constat |
| --- | --- |
| Windows | 11 Professionnel 26H2, build 26300, 64 bits |
| Matériel | MSI MS-7C56, Ryzen 5 5600X (6 cœurs, 12 threads), 32 Go |
| Virtualisation | Active dans le firmware ; hyperviseur Microsoft déjà actif (WSL 2) ; Hyper-V complet non installé |
| Sécurité | UEFI, Secure Boot actif, VBS et HVCI actifs |
| Outils | SDK 10.0.26100 seul : ni WDK, ni WinDbg, ni Debugging Tools ; aucun hyperviseur tiers |
| Disque | D: 381 Go libres (la VM y sera) |

## Choix

### Hyperviseur : VMware Workstation Pro

| Option | Passage USB du scanner | Avec l'hyperviseur Windows actif | Verdict |
| --- | --- | --- | --- |
| **VMware Workstation Pro** (gratuit en usage personnel) | Périphérique brut : l'invité le voit derrière un xHCI virtuel et le lie comme un vrai appareil | Tourne au-dessus de Windows Hypervisor Platform, sans couper VBS ni WSL | **Retenu** |
| Hyper-V | Impossible sur Windows client : DDA est réservé à Windows Server (et passe un contrôleur PCIe entier) ; la session améliorée ne redirige que des classes via RDP | Natif | Écarté |
| Hyper-V + USB/IP (usbipd-win, usbip-win2) | Derrière un contrôleur virtuel logiciel, lui-même pilote noyau tiers signé en test | Natif | Écarté : une couche noyau tierce entre notre code et les URB |
| VirtualBox | Oui | Mode dégradé « NEM », Windows 11 invité lent et instable | Écarté |

Vérifié en 5d : le passage USB fonctionne au-dessus de l'hyperviseur Windows (VMware en mode « ULM », sur Windows Hypervisor Platform).

### Débogage noyau : KDNET, série en secours

- **KDNET** (UDP) : méthode recommandée par Microsoft, rapide (symboles, vidages, traces). La carte émulée par VMware, Intel 82574L (« e1000e »), figure dans la liste des cartes prises en charge par KDNET. Coût : une règle de pare-feu entrante sur Medabot, UDP 50000, limitée à l'adresse de la VM (voir 5e pour sa portée exacte).
- **Secours** : port série virtuel sur tube nommé, sans carte réseau ni pare-feu, mais à 115 200 bauds (symboles très lents).
- Écarté : le débogage local sur Medabot, en lecture seule (ni point d'arrêt ni reprise après plantage).
- Débogueur : WinDbg de Microsoft (version actuelle), sur Medabot.

### Windows de la VM

Windows 11 Enterprise Évaluation (ISO gratuite du centre d'évaluation Microsoft, 90 jours, réarmable ; les instantanés évitent de réinstaller). Choix par défaut retenu le 25/10, David ne l'ayant pas contesté avec le « go ». Le plan visait une version publique plutôt que celle de Medabot ; en pratique, l'ISO d'évaluation du jour est la 26H2, build 26300.9457, la même branche que Medabot (`vertarget` affiche un noyau 26100 : la 26H2 repose sur la base ge_release de 24H2, comme l'indique le nom de l'ISO).

Réglages retenus en 5c (VM créée par commandes, voir plus bas) : UEFI, **Secure Boot coupé dès la création** (sinon le test-signing est refusé), **pas de TPM virtuel** (VMware ne l'accepte qu'avec le chiffrement de la VM, que `vmcli` ne sait pas faire ; l'installateur de Windows 11 est contourné par les clés `LabConfig`, palliatif signalé), intégrité de la mémoire coupée dans l'invité ; 4 processeurs virtuels, 8 Go de RAM, disque NVMe de 80 Go sur D:, carte réseau e1000e en **NAT** (VMnet8 : Internet pour l'invité, et KDNET y fonctionne aussi bien qu'en hôte seul). Pourquoi garder le NAT après l'installation plutôt que repasser en hôte seul : l'évaluation se réarme et se met à jour par Internet. Revers : Windows Update peut redémarrer une VM en test-signing et en débogage ; à suspendre (Paramètres > Windows Update > Suspendre) pendant les séances de l'étape 6, ou repasser en hôte seul (VMnet1) et changer `hostip` de KDNET.

### WDK : construction toujours à la main

WDK **10.0.26100**, la version du SDK déjà installé. Le pilote se construira par notre `Makefile` nmake : `cl` avec `/kernel`, `link /DRIVER`, sans projet MSBuild généré, pour voir chaque option et sa raison. Le WDK apporte les en-têtes `km` et `wdf`, les bibliothèques KMDF, `stampinf`, `inf2cat`, `infverif` et `tracewpp`. Pourquoi pas l'EWDK (ISO autonome) : il embarque un second compilateur alors que les Build Tools 2022 sont déjà là.

### Le faux disque dans la VM

Au premier branchement, le Windows invité lierait le scanner à USBSTOR et monterait le volume FAT12. Règle « jamais écrire sur F: » : **montage automatique coupé dans la VM (`mountvol /N`) avant le premier passage du scanner**, puis bascule sous WinUSB par `bascule_winusb.exe`, comme à l'étape 2.

## Sous-étapes

| Sous-étape | Contenu | Qui | Accord écrit de David |
| --- | --- | --- | --- |
| 5a | Ce document, passation et historique | Claude | Non |
| 5b | Point de restauration de Medabot, sauvegarde du jour vérifiée (restic Drive 12:20, WSL 12:28 ; Kopia local non relu) ; installation de VMware Workstation Pro, WinDbg, WDK 10.0.26100 et Debugging Tools for Windows (pour `kdnet.exe`) ; inventaire relu | David, Claude vérifie | **Oui** (binaires tiers) |
| 5c | VM créée par commandes (`banc/vm/`), Windows installé sans clic, VMware Tools, instantané `windows-propre` | Claude, David pour la console de la VM | **Oui** (Secure Boot de la VM, Tools) |
| 5d | Montage automatique coupé, scanner passé à la VM, `bascule_winusb.exe`, puis `ds720d descripteurs`, `inquiry`, `etat` dans la VM ; traces comparées à Medabot et à une capture USBPcap faite sur Medabot | Claude, David pour l'admin dans la VM | Non (commandes déjà autorisées) |
| 5e | `bcdedit /debug on` et `/dbgsettings net` dans la VM, règle de pare-feu sur Medabot, WinDbg attaché, arrêt et reprise, instantané `debug-pret` | David, Claude guide et vérifie | **Oui** (bcdedit de la VM, pare-feu de Medabot) |
| 5f | Test-signing dans la VM, certificat de test, pilote minimal fait main (`DriverEntry`, un `DbgPrint`, déchargement ; aucun matériel) construit par nmake, signé, chargé dans la VM, message lu dans WinDbg | Claude écrit, David charge | **Oui** (bcdedit de la VM, premier chargement) |
| 5g | Relecture de fond, CLAUDE.md, HISTORIQUE.md, tag `etape-5` | Claude | Non |

## Installé en 5b (25/10)

| Élément | Version, emplacement |
| --- | --- |
| Point de restauration | Créé par David avant les installations (cliché VSS de 14:46 vu sans élévation) |
| WinDbg | 1.2610 (paquet `Microsoft.WinDbg`) |
| WDK | 10.0.26100.6584 : en-têtes `Include\10.0.26100.0\km`, Debugging Tools apportés avec lui (`Debuggers\x64\kdnet.exe`) |
| VMware Workstation Pro | 26.0.1 (26H1u1, build 25688693), téléchargé depuis le portail Broadcom ; SHA-256 conforme à la page, signature Authenticode « Broadcom Inc » valide |
| Réseaux virtuels | VMnet1 (hôte seul) 192.168.50.1/24 ; VMnet8 (NAT) 192.168.150.1/24, celui de la VM et de KDNET |

Piège du portail Broadcom : le bouton de téléchargement reste sur « Screening Required » tant que le profil n'est pas complet, et la case des conditions ne se coche qu'après avoir ouvert le lien « Terms and Conditions ». Après installation : scanner toujours sous WinUSB, VBS et HVCI intacts.

## La VM, créée par commandes (5c, 25/10)

Tout est dans `banc/vm/`. Se rejoue à l'identique : le `.vmx`, le disque, l'ISO de réponse et l'installation de Windows. Restent manuels : les VMware Tools, le mot de passe du compte, le retrait des CD, `mountvol /N` et les instantanés.

Accord de David : « go » du 25/10 sur le plan de 5c, qui annonçait Secure Boot de la VM coupé, pas de TPM et l'intégrité de la mémoire coupée dans l'invité ; « oui » écrit du 25/10 pour les VMware Tools. L'ISO de Windows a été téléchargée par David lui-même.

1. `creer_vm.ps1 -Iso <ISO Windows>` crée `D:\VM\ds720d-noyau` : disque NVMe par `vmware-vdiskmanager`, `autounattend.iso` par `iso_unattend.py`, et le `.vmx` écrit réglage par réglage (justifications dans le script : VMware réécrit le `.vmx` et n'y garde pas de commentaires). Il ne démarre rien et n'écrase rien.
2. `iso_unattend.py` écrit à la main une image ISO 9660 + Joliet (ECMA-119, noms longs Joliet) qui porte `autounattend.xml` : Medabot n'a pas `oscdimg`. Vérifiée en la montant sous Windows : fichier relu identique. La relecture de 5g y a trouvé une longueur d'enregistrement (LEN_DR) qui ne comptait pas l'octet de remplissage : sans effet avec un seul fichier, corrigée, image relue en suivant LEN_DR dans les deux arbres puis remontée sous Windows.
3. `autounattend.xml` : français, partitions GPT, clés `LabConfig` (TPM et Secure Boot), HVCI coupé, accueil sauté, compte local `david`. Installation de Windows 11 Entreprise Évaluation 26H2 (build 26300.9457, ISO FR conforme à l'empreinte SHA-256 publiée par Microsoft) sans aucun clic dans l'assistant.
4. VMware Tools installés dans l'invité (accord de David) : `vmrun` copie des fichiers et lance des commandes dans la VM. Il exige un mot de passe sur le compte : David l'a posé et rangé dans le gestionnaire d'identifiants de Medabot (`cmdkey /generic:ds720d-vm /user:david /pass`), `invite.ps1` le lit par CredRead sans l'afficher.
5. CD retirés, démarrage sur le disque seul, instantané **`windows-propre`**.

**Attention, faux disque du scanner** : `windows-propre` est antérieur à `mountvol /N` (5d). Après un retour à cet instantané, refaire `mountvol /N` dans la VM avant de lui passer le scanner. Et jamais de scanner connecté à la VM pendant une installation de Windows : `autounattend.xml` efface le disque 0, qui pourrait être son volume de 1 Mo.

État relevé par `invite.ps1 etat` : Secure Boot coupé, VBS et HVCI à 0, carte Intel 82574L (e1000e) en 192.168.150.128, contrôleurs EHCI et xHCI présents, aucun volume en dehors de C:.

Pièges rencontrés :
- Au premier démarrage, l'avis de VMware sur les atténuations du canal latéral bloque la mise sous tension jusqu'à un clic : `msg.autoAnswer = "TRUE"` y répond désormais. Palliatif : il répond aussi à toutes les autres questions, dont « VM déplacée ou copiée ? », qui changerait l'adresse MAC, donc peut-être l'adresse IP de la règle de pare-feu. `uuid.action = "keep"` fige cette réponse (ajouté au `.vmx` de la VM en 5g, VM arrêtée, et à `creer_vm.ps1`).
- Démarrer sur le CD d'abord fait réafficher « Press any key to boot from CD » à chaque redémarrage : une touche de trop relance l'installation. Ordre retenu : disque d'abord (vierge, le firmware passe au CD), CD retiré ensuite.
- `vmcli MKS sendKeyEvent` n'atteint pas le gestionnaire de démarrage du firmware : il faut la console de VMware.
- `vmrun runProgramInGuest` recolle les arguments en une ligne : un `-Command` PowerShell avec guillemets et accolades n'y survit pas, d'où le passage par un fichier `.ps1` copié dans l'invité.
- Une fenêtre de VMware propose de connecter à la VM chaque nouveau périphérique USB : toujours répondre « hôte » tant que la 5d n'a pas coupé le montage automatique dans l'invité.

## Le scanner dans la VM (5d, 25/10)

1. Montage automatique coupé dans l'invité (`mountvol /N`, en admin par David), vérifié : `NoAutoMount=1`.
2. Capture USBPcap lancée sur Medabot (`5d-vm`), puis scanner passé à la VM (VM > Périphériques amovibles > Brother DS-720D > Connecter).
3. Windows invité le lie d'abord à USBSTOR et le sonde : TEST UNIT READY, READ CAPACITY, MODE SENSE, READ(10) de 303 104 o au total. **Aucune écriture**, aucune lettre de lecteur. `bascule_winusb.exe --oui` (en admin dans la VM) le passe ensuite sous WinUSB, comme à l'étape 2 sur Medabot.
4. `ds720d descripteurs`, `inquiry` et `etat` lancés dans la VM par `invite.ps1` (le programme tourne sans élévation, comme sur Medabot) : tous réussis.

Contrôle croisé : concordance parfaite entre nos traces de la VM et la capture faite sur Medabot (18, 25 et 105 lignes), et entre nos traces de la VM et celles de Medabot aux étapes 2 et 3. Le passage par VMware est transparent pour le protocole.

Constat utile pour l'étape 6 : **USBPcap sur Medabot voit le trafic que la VM échange avec le scanner**, avec les mêmes adresses d'endpoints et les mêmes CBW. Le pilote noyau dans la VM pourra donc être contrôlé de l'extérieur, par le même banc qu'aux étapes 2 à 4, en plus de ses traces WPP. Réserve : la concordance n'est vérifiée que sur de petits transferts ; pour les lectures d'image de 64 Kio, VMware pourrait découper ou regrouper les URB côté hôte, à vérifier au premier scan depuis la VM.

Le scanner a été rattaché par VMware au contrôleur xHCI virtuel (journal de la VM : `virtPath:usb_xhci:5`).

Le scanner reste attaché à la VM jusqu'à ce qu'on le rende à Medabot (même menu, Déconnecter) ; il y retrouve WinUSB.

## Débogage noyau par KDNET (5e, 25/10)

Accord écrit de David le 25/10 pour bcdedit dans la VM et la règle de pare-feu de Medabot.

1. Instantané `avant-debug` (VM figée avant toute modification de son démarrage).
2. Dans la VM, en admin, par David : `bcdedit /debug on` puis `bcdedit /dbgsettings net hostip:192.168.150.1 port:50000`. bcdedit génère la clé de session : elle reste chez David, ni dans le dépôt ni dans le fil.
3. Sur Medabot, en admin, par David : `New-NetFirewallRule -DisplayName "ds720d KDNET (VM)" -Direction Inbound -Protocol UDP -LocalPort 50000 -RemoteAddress 192.168.150.128 -Action Allow`. Portée réelle : seule l'adresse distante est filtrée, sur toutes les interfaces, tous les profils et tous les programmes ; un paquet du réseau local usurpant 192.168.150.128 passerait (risque faible : KDNET authentifie par la clé). Resserrée en 5g par David : `Set-NetFirewallRule -DisplayName "ds720d KDNET (VM)" -LocalAddress 192.168.150.1` ; relue ensuite : adresse locale 192.168.150.1, distante 192.168.150.128. Pas de filtre par programme : le chemin de WinDbg (paquet MSIX) change à chaque mise à jour.
4. WinDbg sur Medabot : Attach to kernel, Net, port 50000 et la clé ; redémarrage de la VM.

Résultat : « Connected to target 192.168.150.128 on port 50000 on local IP 192.168.150.1 ». Dans l'invité, la carte e1000e passe sous « Microsoft Kernel Debug Network Adapter », même adresse : le réseau de la VM et KDNET partagent la carte. Arrêt (Break), `vertarget` (noyau 26100, 4 processeurs, x64), `lm m winusb` (WinUSB chargé), `!devnode 0 1 WINUSB` (le scanner, `DeviceNodeStarted`), puis `g` : la VM repart. Instantané **`debug-pret`**.

Pour s'attacher à nouveau : WinDbg, Attach to kernel, Net, port 50000, la clé ; la VM se connecte à chaque démarrage. La liaison série sur tube nommé, prévue en secours, n'a pas servi.

Retour arrière : revenir à `avant-debug`, ou `bcdedit /debug off` dans la VM ; sur Medabot, `Remove-NetFirewallRule -DisplayName "ds720d KDNET (VM)"`.

## Test-signing et premier pilote (5f, 25/10)

Accord écrit de David le 25/10 pour le certificat de test, `testsigning` dans la VM et le premier chargement d'un pilote.

1. `noyau/bonjour.c` : pilote KMDF non-PnP, sans matériel. `DriverEntry` affiche un message par `DbgPrintEx`, crée l'objet pilote KMDF (`WdfDriverInitNonPnpDriver`), et `EvtDriverUnload` en affiche un autre au déchargement.
2. Construction par `construire.cmd noyau` : cible du `Makefile` écrite à la main (`cl /kernel /GS /X` avec les seuls en-têtes du WDK : `km\crt`, `km`, `shared`, KMDF 1.15 ; `link /DRIVER /SUBSYSTEM:NATIVE /ENTRY:FxDriverEntry /NODEFAULTLIB /RELEASE`). `dumpbin` : sous-système Native, entrée `FxDriverEntry`, imports `ntoskrnl.exe` et `WDFLDR.SYS`.
3. Signature par `noyau/signer.ps1` : certificat auto-signé SHA-256 « CN=ds720d test (VM uniquement) » (empreinte `B23EC996E38B082462453EFB9F495CCC2B93C2AF`), dans le magasin personnel de l'utilisateur de Medabot, clé privée non exportable ; `signtool sign /fd sha256`. La partie publique est exportée dans `out\noyau\ds720d-test.cer` ; la VM n'a pas eu besoin de l'importer.
4. Instantané `avant-test-signing`, puis `bcdedit /set testsigning on` dans la VM et redémarrage. Options de démarrage de la VM relues : `TESTSIGNING`, `DEBUG`, `DEBUGPORT=NET`. Celles de Medabot n'ont pas bougé (ni `TESTSIGNING` ni `DEBUG`).
5. Dans la VM, en admin : `sc.exe create ds720d_bonjour type= kernel start= demand binPath= C:\Users\Public\ds720d\bonjour.sys`, puis `sc.exe start`, `sc.exe stop` et `sc.exe delete`. WinDbg affiche « DriverEntry, KMDF 1.15, service …\ds720d_bonjour », « objet pilote KMDF cree », puis « dechargement » ; `sc` passe par RUNNING puis STOPPED, codes de sortie 0.

Pièges :
- nmake met en majuscules le nom des variables d'environnement qu'il reprend (`$(VCToolsInstallDir)` reste vide) ; on n'en a finalement pas besoin, `km\crt` du WDK fournit les en-têtes C du noyau.
- `wdfrequest.h` de KMDF lève l'avertissement C4324 (alignement voulu) : coupé d'abord par `/wd4324`, puis, après la relecture de 5g, seulement autour de `#include <wdf.h>` (`#pragma warning(push/pop)`), pour ne pas le couper sur notre code.

Après la relecture de 5g, `bonjour.sys` a été reconstruit (pragma ci-dessus, `/OPT:REF /OPT:ICF` comme le WDK, message « KMDF demande 1.15 » : c'est la version demandée à la compilation, `!wdfkd.wdfldr` montrerait la liaison réelle), signé à nouveau et rechargé dans la VM par David (`sc create`, `start`, `stop`, `delete`) : mêmes trois messages dans WinDbg, codes de sortie 0.
- Un premier `bcdedit /set testsigning on` a été tapé par erreur dans un Terminal de Medabot : refusé par Secure Boot (« protégée par la stratégie de démarrage sécurisé »), rien n'a changé. Toujours vérifier `hostname` (`DS720D-NOYAU` dans la VM) avant une commande d'administration.
- Un instantané à chaud écrit les 8 Go de mémoire de la VM sur D: (plus de dix minutes), mais l'état est figé dès le départ : on peut continuer à travailler pendant l'écriture.

Instantané **`test-signing-pret`** : VM avec KDNET et test-signing, scanner sous WinUSB, prête pour l'étape 6.

## Pièges du banc relevés à l'étape 6

Détail dans [pilote.md](pilote.md), 6d.

- **Veille de Windows dans la VM** : après 15 minutes d'inactivité sur secteur, Windows demande la veille S1 ; VMware la traite en suspendant la VM, ce qui rend le scanner à Medabot. Coupée le 25/10 par David (`powercfg /change standby-timeout-ac 0` dans la VM ; l'hibernation l'était déjà). À refaire après un retour à un instantané antérieur à `avant-6d-bis`.
- **Ne jamais suspendre la VM** pendant que le scanner lui est passé : même effet, et la reprise d'une VM attachée à KDNET a précédé une NMI (0x80).
- **KDNET et rafales de DbgPrint** : deux plantages 0x80 NMI_HARDWARE_FAILURE juste après des rafales de messages vers WinDbg ; aucun sur 80 cycles sans ces messages (40 sans débogueur, 40 avec). Le pilote ne recopie plus ses traces vers WinDbg que sur demande.
- **Instantanés** : `avant-6d` s'est terminé pendant la suspension ci-dessus ; `avant-6d-bis` l'a remplacé, pris scanner hors de la VM. Un instantané « à chaud » gèle la VM un instant (0,6 s pour `avant-6d-bis` dans le journal de VMware), puis écrit la mémoire pendant que la VM tourne.

## Retour arrière

- **VM** : revenir à un instantané (`windows-propre`, `avant-debug`, `debug-pret`, `avant-test-signing`, `test-signing-pret`, puis ceux de l'étape 6 : `avant-6b`, `avant-6c`, `avant-6d`, `avant-6d-bis`…), ou supprimer la VM ; rien ne fuit vers Medabot. Après `windows-propre`, refaire `mountvol /N` avant tout passage du scanner.
- **Ce que l'étape 5 a changé sur Medabot**, et comment le défaire :
  - installations de 5b (VMware, WinDbg, WDK) : les désinstaller depuis les paramètres ;
  - règle de pare-feu de 5e : `Remove-NetFirewallRule -DisplayName "ds720d KDNET (VM)"` ;
  - identifiant du compte de la VM (5c) : `cmdkey /delete:ds720d-vm` ;
  - certificat de test (5f) : `Remove-Item Cert:\CurrentUser\My\B23EC996E38B082462453EFB9F495CCC2B93C2AF` ;
  - fichiers de travail de `invite.ps1` : `%TEMP%\ds720d-invite.*` et `%TEMP%\ds720d-etat-vm.*` ;
  - ISO de Windows (8,2 Go) : déplacée en 5g de `D:\Downloads` (compris dans la sauvegarde restic Drive) vers `D:\VM\iso` ; la supprimer avec la VM ;
  - en dernier recours, le point de restauration de 5b.
  Bcdedit, Secure Boot, VBS et HVCI de Medabot n'ont pas changé.
- **Scanner** : quand VMware le rend à Medabot, il retrouve WinUSB ; sinon débrancher et rebrancher. Retour au pilote Brother : [winusb.md](winusb.md).
