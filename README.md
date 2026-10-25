# ds720d-scan

Pilote écrit à la main, en C, pour le scanner mobile **Brother DS-720D** sous Windows 11, sans bibliothèque ni pilote propriétaire.

Projet d'apprentissage : rétro-ingénierie du protocole USB par captures, prototype en espace utilisateur sur WinUSB, puis pilote noyau KMDF.

État : étape 2 terminée. Le scanner est sous WinUSB, et `ds720d.exe` lit ses descripteurs, demande son nombre de LUN et lui envoie un INQUIRY écrit à la main. Étape 3, rejouer un scan, à venir.

Construction : `construire.cmd` (Build Tools Visual Studio 2022 et Windows SDK), puis `out\ds720d.exe inquiry --trace C:\Users\morva\ds720d-captures\traces\essai.txt`. Les traces vont à côté des captures, hors du dépôt : `construire.cmd clean` efface tout `out\`. Voir [docs/passation.md](docs/passation.md) et [HISTORIQUE.md](HISTORIQUE.md).
