# Règles du projet ds720d-scan

Pilote écrit à la main pour le scanner USB **Brother DS-720D** (`VID_04F9&PID_60E2`) sous Windows 11, sur le PC Medabot. Projet d'apprentissage : descendre au plus bas niveau possible.

`CLAUDE.md`, [docs/passation.md](docs/passation.md) et [HISTORIQUE.md](HISTORIQUE.md) font foi pour l'architecture, les décisions et la feuille de route.

## Architecture (décidée le 25/10/2026)

- Langage : **C** pour tout ce qui parle au scanner. Le banc de test (analyse des captures) peut être en Python, écrit à la main avec la bibliothèque standard seulement.
- Cible finale : **pilote noyau KMDF** (WDF/WDK).
- Phase d'apprentissage d'abord, en espace utilisateur sur **WinUSB** : on apprend le protocole sans risquer d'écran bleu. Passer le scanner sous WinUSB coupe le logiciel Brother : toutes les captures de référence se font avant.
- Aucune bibliothèque qui fait le travail à notre place : ni SANE, ni TWAIN/WIA, ni pilote Brother, ni libusb, ni pyshark/scapy.
- Niveau le plus bas partout : descripteurs, endpoints, URB, transferts bulk, CBW/CSW écrits octet par octet, commandes SCSI encapsulées.
- Code C (`src/`) : `peripherique.c` (WinUSB : recherche par SetupAPI, transferts de contrôle et bulk), `bot.c` (transport Bulk-Only, CBW et CSW, Reset Recovery), `tunnel.c` (commandes vendeur 0xC5 et 0xC3, sélecteurs et dépôts observés seulement), `trace.c` (trace au format commun), `ds720d.c` (le programme), `image.c` et `convertir.c` (image brute vers PGM ou PNG écrits à la main, sans zlib). Construction : `construire.cmd` (MSVC des Build Tools 2022 et Windows SDK 10.0.26100, `nmake` sur le `Makefile`), sorties dans `out/`, compilation en `/W4 /WX`.
- Depuis l'étape 2, le scanner est sous **WinUSB** (classe USBDevice), posé par `out\bascule_winusb.exe --oui` en admin ; retour au pilote Brother par deux commandes `pnputil` : [docs/winusb.md](docs/winusb.md). `ds720d.exe` refuse d'ouvrir le scanner s'il n'est pas sous WinUSB.

## Sources qui font foi

- Les captures USBPcap du logiciel Brother et les specs : USB 2.0, USB Mass Storage Bulk-Only Transport 1.0 (BOT), SCSI (SPC/SBC), doc WDK.
- **Chaque commande envoyée cite sa source** en commentaire : section de spec ou numéro de trame de capture.
- Le code d'autres projets (backend SANE avision…) peut aider à lire une capture, jamais servir de source.

## Sécurité matérielle

- **Ne jamais écrire sur le faux disque du scanner** (volume FAT12 de 1 Mo, lettre F: sur Medabot) : pas de WRITE, pas de FORMAT, pas d'écriture de fichier.
- N'envoyer aucune commande SCSI qui n'est ni observée dans une capture ni documentée dans une spec. Une commande vendeur observée mais d'effet inconnu (écritures 0xC5 notamment) ne s'envoie qu'une fois son rôle compris et avec l'accord de David. Accord écrit du 25/10/2026 pour les SEND vendeur 0x95, 0x96 et 0x83 avec les octets de 2a (ceux du pilote TWAIN avant chaque scan) ; toute autre valeur le redemande. `src/tunnel.c` ne laisse partir que des dépôts identiques octet pour octet à un dépôt observé.
- Jamais de mise à jour du firmware.
- Phase noyau : mode test-signing, point de restauration et débogage noyau (WinDbg, idéalement dans une VM Windows avec passage USB) mis en place **avec l'accord écrit de David** avant le premier chargement du pilote. Toute modification de bcdedit, Secure Boot ou de la signature des pilotes demande son accord explicite.
- Rien installer, désinstaller, télécharger ni exécuter de binaire tiers sans l'accord écrit de David. Le mode auto de Claude Code bloque `winget install` : c'est David qui lance les installations, et tout ce qui demande les droits admin (Claude tourne sans élévation).
- Le logiciel Brother (service Mobile_Series, TWAIN, NvUSBScan.dll) reste en place tant qu'il sert de référence ; son retrait se décide avec David. Sous WinUSB, il ne voit plus le scanner : pour une nouvelle capture de référence, revenir d'abord à USBSTOR ([docs/winusb.md](docs/winusb.md)).

## Banc de test

- Référence : captures USBPcap du logiciel Brother, rangées **hors du dépôt** dans `C:\Users\morva\ds720d-captures\` et consignées (empreinte, scénario) dans [docs/captures.md](docs/captures.md). Elles contiennent des images de documents : jamais commitées, pas plus que les images BMP.
- Outils (`banc/`) : `analyse_capture.py` (décodage fait main), `contre_verif.py` (comparaison avec tshark), `capture.py` et la tâche planifiée `ds720d-capture` (captures sans élévation), `twain_banc.py` (scans du pilote Brother), `compare_traces.py` (deux traces au format commun, sans les colonnes trame, temps et adresse), `verif_blocs.py` (lectures 0xC3 conformes aux blocs annoncés), `extrait_image.py` (blocs d'image d'une capture recollés en fichier brut) et `image_brute.py` (brut vers BMP, comparaison au BMP du pilote Brother), `verif_png.py` (PNG et PGM de `convertir.exe` relus par la zlib de Python et comparés au brut, point par point). Bruts et BMP restent dans `ds720d-captures\images\`. Le protocole vendeur décodé par l'analyseur est décrit dans [docs/protocole.md](docs/protocole.md). Essais sans matériel : `out\essai_trace.exe` (texte de la trace contre l'analyseur), `out\essai_bot.exe` (garde-fous du transport Bulk-Only et du tunnel contre un faux scanner) et `out\essai_image.exe` (CRC-32 et Adler-32 contre des valeurs publiées). `src/bot.c` refuse tout opcode absent de sa liste blanche, qui ne s'allonge que d'opcodes observés.
- TWAIN ne sert qu'à faire travailler le pilote Brother pour les captures de référence (accord de David du 25/10) ; jamais dans notre code.
- Toujours capturer avec `-s 262144` ; `--resume` de l'analyseur doit afficher « trames tronquées à la capture (snaplen) : 0 ».
- Le numéro de série du scanner (descripteur STRING, réponses 0xC5 de 128 et 165 o, données de SEND 0x85 emballé envoyées par Capture Tool, réglages TWAIN 0x1024 et 0x9214) ne va jamais dans le dépôt : l'analyseur le masque par défaut (`--serie` pour le voir), le reste se vérifie avant de copier une trace.
- Notre code trace chaque transfert qu'il émet au [format commun](docs/format-trace.md), pour comparer ligne à ligne avec les captures. En phase noyau : traces WPP/DbgPrint.
- Contrôle croisé à chaque essai sur le scanner : notre trace (`--trace`), la capture USBPcap de notre passage et la référence du pilote Windows doivent concorder (`compare_traces.py`, `--sans-tags` contre la référence). Nos captures sont consignées dans [docs/captures.md](docs/captures.md).
- Après un passage par `pnputil`, USBPcap ne voit plus le scanner : le débrancher et le rebrancher avant de capturer.

## Façon de travailler

- Répondre en français, de façon pédagogique : expliquer chaque action au fil de l'eau. Code commenté en français.
- Claude écrit le code, retient le meilleur choix et justifie en commentaire pourquoi (et pourquoi pas les autres options). Signaler tout palliatif comme tel.
- Une étape à la fois, vérifiée sur le vrai scanner avant la suivante. Grosse étape : sous-étapes taguées, plan relu avant le « go ».
- Un commit par sous-étape, identité `David Morvan <morvan.david.44@gmail.com>`. Ne commiter qu'après avoir lu le résultat des tests, jamais dans une commande qui enchaîne test et commit.
- Relecture de fond avant le premier push de chaque étape. David pousse lui-même ; push forcé seulement avec `--force-with-lease=main:<hash>`.
- En fin d'étape : mettre à jour `CLAUDE.md` et `HISTORIQUE.md`.
