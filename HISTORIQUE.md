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
- 1c : capture d'un scan gris 300 dpi. Le protocole Brother est fait de **commandes SCSI vendeur** et non d'écritures de secteurs : 0xC5 pour l'état et les réglages, 0xC3 pour lire l'image par blocs de 64 Kio. Bonne nouvelle pour la règle « jamais écrire sur F: ».
- 1d : analyseur de captures fait main (`banc/analyse_capture.py`, Python sans dépendance) et format de trace commun (`docs/format-trace.md`). Contre-vérifié par tshark (`banc/contre_verif.py`) : 0 écart sur les deux captures. Il révèle que la capture 1c a coupé les blocs d'image de 64 Kio (longueur de capture par défaut de 65 535 o) : il faut la refaire avec `-s 262144` avant de passer sous WinUSB.
- **Décision (David)** : Claude pilote lui-même captures et scans. Captures via une tâche planifiée qui exécute un script admin verrouillé (1e-1) ; scans via un client TWAIN de banc qui fait travailler le pilote Brother (1e-2). TWAIN reste cantonné à la référence.
- 1e-3 : série complète de captures (gris, couleur, noir et blanc 300 dpi, gris 600 dpi, recto-verso, cas « pas de papier », insertions sans scan). Jusqu'à 300 dpi, le scanner envoie le même volume quel que soit le mode ou la résolution : la conversion se ferait sur le PC. Bonus demandés par David : gris 150 dpi et une photo couleur pour repérer les canaux.
- Relecture de fond avant le push : script admin durci (liens refusés, journal déplacé dans `C:\ProgramData\ds720d`, arrêt limité à ses propres processus), installation avec propriétaire forcé, numéro de série masqué par l'analyseur, `.gitignore` complété, conversions TWAIN corrigées, règle sur les commandes vendeur d'effet inconnu.
- **Fin de l'étape 1.** Prochaine étape : chaîne C installée par David, puis passage du scanner sous WinUSB et premier programme C (descripteurs, Get Max LUN, INQUIRY encapsulé à la main).

## 25/10/2026 — Étape 2 : WinUSB et premier programme C

- Installation par David des Build Tools Visual Studio 2022 (17.14) avec le compilateur C et le Windows SDK 10.0.26100. Choix de MSVC plutôt que MinGW ou clang : le WDK de l'étape 6 l'exige, et `winusb.h` vient du SDK.
- 2a : dernière capture de référence avant la bascule, avec Brother Button Manager arrêté. Sans ses interrogations de fond, il ne reste que la séquence du pilote TWAIN : la référence de l'étape 3. Elle suggère (déduction) que les écritures 0xC5 transportent des commandes de scanner SCSI emballées, dont un SET WINDOW qui contient « 300 × 300 ».
- 2b : `construire.cmd` et un `Makefile` nmake écrit à la main ; `src/trace.c` écrit le format commun, avec le texte de l'analyseur pour les échanges réussis ; `banc/compare_traces.py` compare deux traces. Essai sans matériel sur les octets de 1b : concordance parfaite.
- 2c : bascule sous WinUSB. **Le Gestionnaire de périphériques refuse** `winusb.inf`, même par « Disque fourni » : il ne propose que des pilotes de la classe du scanner (USB), alors que `winusb.inf` est de classe USBDevice. **Décision** : un outil C, `bascule_winusb.exe`, fait le choix par SetupAPI (changement de classe, modèle de section WINUSB, `DiInstallDevice`), lancé par David en admin. Aller, retour par `pnputil`, puis nouvel aller : tous réussis, le disque WD voisin intact.
- 2d : `ds720d descripteurs` ouvre le scanner par l'interface `GUID_DEVINTERFACE_USB_DEVICE` (le modèle générique de WinUSB n'en déclare pas d'autre) et lit DEVICE, CONFIGURATION et STRING 0 avec des paquets SETUP faits main. Piège : après `pnputil`, USBPcap ne voyait plus le scanner ; un rebranchement l'a rattaché, et le scanner reste sous WinUSB.
- 2e : GET_MAX_LUN répond 0, un seul LUN.
- 2f : `src/bot.c`, transport Bulk-Only ; premier INQUIRY dans un CBW écrit champ par champ : « Brother », « DS-720D », « 0.27 », statut 0.
- Contrôle croisé de 2d à 2f : notre trace, la capture de notre passage et la référence 1b concordent ligne pour ligne ; `contre_verif.py` (tshark) : 0 écart.
- Relecture de fond avant le push, par une relecture indépendante : aucun défaut bloquant, aucune trace du numéro de série dans l'historique. Corrections : liste blanche d'opcodes dans `bot.c` (tout le reste est refusé avant l'envoi), contrôle que l'appareil tourne vraiment sous WinUSB (`CM_Get_DevNode_Status`), tag BOT de départ variable et CSW contrôlé jusqu'au bout (BOT §6.3.2, statut 2), masquage des réponses porteuses du numéro de série, bornes de parcours et retours d'API vérifiés, comparateur qui échoue sur une trace vide, textes de trace alignés (sense, capacité, blancs), traces rangées hors de `out\`. Nouvel essai sans matériel `essai_bot.exe` (9 cas conformes) et INQUIRY rejoué sur le scanner : concordance parfaite.
- **Fin de l'étape 2.** Prochaine étape : rejouer la séquence de scan de `2a-gris-300-recto-sans-bm`, en comprenant d'abord chaque écriture 0xC5 avant de l'envoyer (accord de David requis pour celles dont l'effet reste inconnu).

## 25/10/2026 — Étape 3 : premier scan depuis notre code

- Décodage de la capture 2a : **0xC5 est un tunnel**. Son sélecteur `02 03 00` dépose une commande du jeu « Scanner devices » de SCSI-2 (chapitre 15) : SEND, SET WINDOW, RESERVE UNIT, SCAN, READ, RELEASE UNIT ; les autres sélecteurs lisent la réponse, le statut, l'état du bloc d'image ou des sondages. 0xC3 lit chaque bloc d'image à l'adresse que le scanner annonce. **Décision (David)** : plan en sept sous-étapes (3a à 3g), « go » le 25/10.
- 3a : décodage dans l'analyseur et [docs/protocole.md](docs/protocole.md), vérifié et déduit séparés. Aucune forme de CDB inconnue dans les 17 captures. Gris, couleur et noir et blanc envoient la même fenêtre RVB 8 bits : le scanner scanne toujours en couleur, le pilote Brother convertit sur le PC. Trouvé en route : Capture Tool envoie le numéro de série dans un SEND 0x85, désormais masqué.
- 3b : image brute reconstituée hors ligne et comparée aux BMP du pilote TWAIN (corrélation 0,985 en gris, 0,999 en couleur) : lignes de 3 plans de 2 592 points, rouge, vert, bleu. Le pilote rogne 4 points et 11 lignes, prend le plan vert pour le gris et applique une courbe de tons.
- 3c : lectures par le tunnel sur le scanner (signature « NOVA », identifiants 0x04F9 et 0x60E2) ; reprise sur erreur Bulk-Only selon la spec (STALL des données ou du CSW, Reset Recovery BOT §5.3.4), le déblocage passant par `WinUsb_ResetPipe`.
- 3d : commandes de lecture déposées dans le tunnel, avec la chorégraphie du pilote (sondages, dépôt, réponse, statut). L'opcode 0x08 dit si une feuille est engagée. Seuls partent des dépôts identiques octet pour octet à un dépôt observé.
- 3e : **accord écrit de David** (25/10) pour les trois SEND vendeur d'effet inconnu (0x95, 0x96, 0x83), envoyés par le pilote TWAIN avant chaque scan. Premier essai interrompu par un faux contact du câble (le scanner quitte le bus au 5e bloc) ; second essai réussi : 20 blocs, 1 600 lignes, même suite de commandes que 2a, image identique à celle de la capture.
- 3f : PGM et PNG écrits à la main, sans zlib : blocs deflate « stockés », CRC-32 et Adler-32 faits main, vérifiés par la zlib de Python point par point. L'image reste brute, donc sombre.
- Relecture de fond avant le push, par une relecture indépendante : aucun défaut bloquant, aucune trace du numéro de série dans l'historique. Corrections : RELEASE UNIT tenté dès que RESERVE l'a été, Ctrl+C qui libère l'unité, plafond de blocs par page, lectures du tunnel contrôlées par sélecteur et longueur, pHYs du PNG selon la résolution verticale, masquage du numéro de série aligné entre l'analyseur et `trace.c`, docs périmées reprises. Constat documenté : sous USBSTOR, le scanner répète dans les CSW 0xC5 le résidu d'un MODE SENSE de Windows (« résidu collé ») ; `bot.c` garde la règle de BOT §6.3.2. Scan de contrôle (`3g-scan`) : concordance complète.
- **Fin de l'étape 3.** Prochaine étape : rendu (courbe de tons, recadrage), recto-verso et 600 dpi sur le même protocole, avant la préparation noyau.
