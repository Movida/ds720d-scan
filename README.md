# ds720d-scan

Pilote écrit à la main, en C, pour le scanner mobile **Brother DS-720D** sous Windows 11, sans bibliothèque ni pilote propriétaire.

Projet d'apprentissage : rétro-ingénierie du protocole USB par captures, prototype en espace utilisateur sur WinUSB, puis pilote noyau KMDF.

État : étape 5 terminée. Le scanner est sous WinUSB ; `ds720d.exe scan` lui fait scanner une page (gris, recto-verso, 600 dpi) en rejouant le protocole vendeur du pilote Brother ([docs/protocole.md](docs/protocole.md)), et `convertir.exe` la rend comme le pilote Brother en PGM ou PNG écrits à la main. Le banc noyau est prêt : VM VMware avec passage USB du scanner, débogage KDNET, test-signing, et un premier pilote KMDF d'essai ([docs/noyau.md](docs/noyau.md)). Étape 6 en cours : le pilote KMDF du scanner ([docs/pilote.md](docs/pilote.md)).

Construction : `construire.cmd` (Build Tools Visual Studio 2022 et Windows SDK), puis `out\ds720d.exe scan --sortie C:\Users\morva\ds720d-captures\images\brut\page.brut --trace C:\Users\morva\ds720d-captures\traces\page.txt` et `out\convertir.exe …\page.brut --png …\page.png --couleur`. Images et traces vont à côté des captures, hors du dépôt. `construire.cmd noyau` construit les pilotes de `noyau/` avec le WDK, `noyau\signer.ps1` les signe avec le certificat de test ; ils ne se chargent que dans la VM. `construire.cmd clean` efface tout `out\`. Voir [docs/passation.md](docs/passation.md) et [HISTORIQUE.md](HISTORIQUE.md).
