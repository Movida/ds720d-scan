# Règles du projet ds720d-scan

Pilote écrit à la main pour le scanner USB **Brother DS-720D** (`VID_04F9&PID_60E2`) sous Windows 11, sur le PC Medabot. Projet d'apprentissage : descendre au plus bas niveau possible.

`CLAUDE.md`, [docs/passation.md](docs/passation.md) et [HISTORIQUE.md](HISTORIQUE.md) font foi pour l'architecture, les décisions et la feuille de route.

## Architecture (décidée le 25/10/2026)

- Langage : **C** pour tout ce qui parle au scanner. Le banc de test (analyse des captures) peut être en Python, écrit à la main avec la bibliothèque standard seulement.
- Cible finale : **pilote noyau KMDF** (WDF/WDK).
- Phase d'apprentissage d'abord, en espace utilisateur sur **WinUSB** : on apprend le protocole sans risquer d'écran bleu. Passer le scanner sous WinUSB coupe le logiciel Brother : toutes les captures de référence se font avant.
- Aucune bibliothèque qui fait le travail à notre place : ni SANE, ni TWAIN/WIA, ni pilote Brother, ni libusb, ni pyshark/scapy.
- Niveau le plus bas partout : descripteurs, endpoints, URB, transferts bulk, CBW/CSW écrits octet par octet, commandes SCSI encapsulées.

## Sources qui font foi

- Les captures USBPcap du logiciel Brother et les specs : USB 2.0, USB Mass Storage Bulk-Only Transport 1.0 (BOT), SCSI (SPC/SBC), doc WDK.
- **Chaque commande envoyée cite sa source** en commentaire : section de spec ou numéro de trame de capture.
- Le code d'autres projets (backend SANE avision…) peut aider à lire une capture, jamais servir de source.

## Sécurité matérielle

- **Ne jamais écrire sur le faux disque du scanner** (volume FAT12 de 1 Mo, lettre F: sur Medabot) : pas de WRITE, pas de FORMAT, pas d'écriture de fichier.
- N'envoyer aucune commande SCSI qui n'est ni observée dans une capture ni documentée dans une spec.
- Jamais de mise à jour du firmware.
- Phase noyau : mode test-signing, point de restauration et débogage noyau (WinDbg, idéalement dans une VM Windows avec passage USB) mis en place **avec l'accord écrit de David** avant le premier chargement du pilote. Toute modification de bcdedit, Secure Boot ou de la signature des pilotes demande son accord explicite.
- Rien installer, désinstaller, télécharger ni exécuter de binaire tiers sans l'accord écrit de David. Le mode auto de Claude Code bloque `winget install` : c'est David qui lance les installations.
- Le logiciel Brother (service Mobile_Series, TWAIN, NvUSBScan.dll) reste en place tant qu'il sert de référence ; son retrait se décide avec David.

## Banc de test

- Référence : captures USBPcap du logiciel Brother, rangées **hors du dépôt** dans `C:\Users\morva\ds720d-captures\`. Elles contiennent des images de documents : jamais commitées.
- Notre code trace chaque transfert qu'il émet, au même format que l'analyseur de captures, pour comparer ligne à ligne. En phase noyau : traces WPP/DbgPrint.

## Façon de travailler

- Répondre en français, de façon pédagogique : expliquer chaque action au fil de l'eau. Code commenté en français.
- Claude écrit le code, retient le meilleur choix et justifie en commentaire pourquoi (et pourquoi pas les autres options). Signaler tout palliatif comme tel.
- Une étape à la fois, vérifiée sur le vrai scanner avant la suivante. Grosse étape : sous-étapes taguées, plan relu avant le « go ».
- Un commit par sous-étape, identité `David Morvan <morvan.david.44@gmail.com>`. Ne commiter qu'après avoir lu le résultat des tests, jamais dans une commande qui enchaîne test et commit.
- Relecture de fond avant le premier push de chaque étape. David pousse lui-même ; push forcé seulement avec `--force-with-lease=main:<hash>`.
- En fin d'étape : mettre à jour `CLAUDE.md` et `HISTORIQUE.md`.
