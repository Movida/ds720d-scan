# ds720d-scan

Pilote écrit à la main, en C, pour le scanner mobile **Brother DS-720D** sous Windows 11, sans bibliothèque ni pilote propriétaire.

Projet d'apprentissage : rétro-ingénierie du protocole USB par captures, prototype en espace utilisateur sur WinUSB, puis pilote noyau KMDF.

État : étape 3 terminée. Le scanner est sous WinUSB, et `ds720d.exe scan` lui fait scanner une page en rejouant le protocole vendeur du pilote Brother ([docs/protocole.md](docs/protocole.md)) ; `convertir.exe` en tire un PGM ou un PNG écrits à la main. Étape 4 : rendu, recto-verso, 600 dpi.

Construction : `construire.cmd` (Build Tools Visual Studio 2022 et Windows SDK), puis `out\ds720d.exe scan --sortie C:\Users\morva\ds720d-captures\images\brut\page.brut --trace C:\Users\morva\ds720d-captures\traces\page.txt` et `out\convertir.exe …\page.brut --png …\page.png --couleur`. Images et traces vont à côté des captures, hors du dépôt. `construire.cmd clean` efface tout `out\`. Voir [docs/passation.md](docs/passation.md) et [HISTORIQUE.md](HISTORIQUE.md).
