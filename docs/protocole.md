# Protocole vendeur du DS-720D

Déchiffré à l'étape 3a à partir des captures du pilote Brother ([captures.md](captures.md)). Il n'existe pas de spécification publique de ce protocole : chaque affirmation renvoie à une trame ou à une section de spec. **Vérifié** veut dire lu dans les octets, **déduit** veut dire interprété sans preuve.

Sauf mention contraire, les trames sont celles de `2a-gris-300-recto-sans-bm.pcap` (adresse 15), la séquence de scan du pilote TWAIN sans Button Manager. L'analyseur (`banc/analyse_capture.py`, section 5) écrit ce décodage sous forme de lignes `|` dans la trace.

Spec de référence pour les commandes emballées : SCSI-2 (X3.131-1994), chapitre 15 « Scanner devices ». Sous-clauses citées d'après la version HTML de travail : §7.2.1 (groupes de codes d'opération), §7.2.7 (octet de contrôle), table 277 (commandes des scanners), §15.2.4 READ, §15.2.5 SCAN, §15.2.6 SEND, §15.2.7 SET WINDOW, §15.3.3.1 (unités de mesure).

## 1. Deux commandes vendeur

Le pilote Brother n'emploie que deux opcodes, 0xC5 et 0xC3, du groupe 6 réservé aux fabricants (SCSI-2 §7.2.1). Leurs CDB font 16 o et ont la même forme dans les 17 captures de référence : l'analyseur signale par `!!` tout écart, et n'en trouve aucun.

| Octets | 0xC5 | 0xC3 |
| --- | --- | --- |
| 0 | `c5` | `c3` |
| 1 | `07`, constant, sens inconnu | `07` |
| 2-5 | 0 | adresse dans la mémoire du scanner, gros-boutiste |
| 6-9 | longueur des données, gros-boutiste, égale à `dCBWDataTransferLength` | idem |
| 10-12 | **sélecteur** | 0 |
| 13-15 | 0 | 0 |

Toutes les commandes de toutes les captures finissent en statut CSW 0.

## 2. 0xC5, un tunnel

### Sélecteurs

| Sélecteur | Sens, taille | Rôle |
| --- | --- | --- |
| `ff 02 00` | IN 4 o | rend `4e 4f 56 41`, « NOVA » : signature du contrôleur NovaTek (vérifié, trame 778) |
| `ff 03 00` à `ff 06 00` | IN 16 o | sondages d'état, intercalés entre tous les échanges. Réponse `10 00 00 00 01 00 00 00 0X 00…` : X vaut 0 pour `ff 03`, 1 pour `ff 04` à `ff 06` (dans 2a, 10 réponses de `ff 04` sur 6 432 ont X = 0). Rôle déduit : drapeaux d'occupation |
| `02 03 00` | OUT n o | **dépose une commande SCSI-2 de scanner** (section 3) |
| `02 01 k` | IN | « en-tête de réponse » : commence toujours par `10 00…`, comme les sondages (déduit : bloc d'état du contrôleur) |
| `02 02 k` | IN | la réponse elle-même |

Le troisième octet `k` du sélecteur `02 01 k` et `02 02 k` dit quelle réponse on lit :

| k | Lu après | Contenu de `02 02 k` |
| --- | --- | --- |
| 0 | une commande qui rend des données (INQUIRY, READ de 2, 16 ou 128 o) | les données (vérifié : INQUIRY emballé de `1b`, trame 22994, type de périphérique 06 = scanner, vendeur « BROTHER ») |
| 1 | toute commande déposée | 4 o, toujours 0 (2 541 réponses dans 2a, 1c et 1e ; déduit : statut SCSI GOOD) |
| 2 | READ image | état du bloc d'image, 24 o (section 4) |
| 3 | rien : lu sans dépôt | `04 f9`, l'idVendor du descripteur DEVICE (vérifié, `1b` trame 20896) |
| 4 | rien : lu sans dépôt | `60 e2`, l'idProduct |

### Déroulé d'une commande

Exemple de la première commande de 2a, trames 806 à 934 :

1. Dépôt `02 03 00` (CBW 806, données 808).
2. Sondages `ff 04`, `ff 06`, `ff 04`, `ff 03`, `ff 03`, `ff 05`.
3. Si la commande rend des données : `02 01 0` (trame 851), un `ff 04`, `02 02 0` (trame 863).
4. Sondages, puis `02 01 1` (trame 905), un `ff 04`, `02 02 1` (trame 917) : statut.

La zone déposée commence par 10 o réservés au CDB emballé (un CDB de 6 o, groupe 0, y est suivi de 4 zéros), puis viennent les données éventuelles. Vérifié : dépôt de 12 o = 10 + 2 pour SEND 0x95 (trame 1755), 89 o = 10 + 0x4F pour SET WINDOW (trame 2067).

## 3. Les commandes emballées

Le premier octet de chaque dépôt est un opcode de la table 277 (commandes des scanners), sauf 0x08. Attention : dans ce jeu, 0x2A est **SEND**, pas WRITE(10). Aucune commande emballée n'écrit de support ni de firmware (pas de WRITE BUFFER, §8.2.17).

### Séquence de scan de 2a

| Données (trame) | Commande emballée | Lecture |
| --- | --- | --- |
| 808, 1130, 1450 | `08 00 00 00 02 00` | opcode absent de la table 277 (READ(6) chez les autres classes) ; rend 2 o, `01 00`. Déduit : « appareil prêt ? » |
| 969, 1291, 1602 | READ type 0xA0 (vendeur), qualificatif 0x0A0D, 2 o | rend `01 00` |
| 1755 | SEND type 0x95 (vendeur), qualificatif 0x0001, 2 o : `00 00` | effet inconnu |
| 1859 | SEND type 0x96 (vendeur), qualificatif 0x0001, 2 o : `00 00` | effet inconnu |
| 1961 | SEND type 0x83 (vendeur), 18 o : `04 00 00 00 00 00` trois fois | effet inconnu ; trois groupes, un par canal R, V, B (déduit) |
| 2067 | SET WINDOW, 79 o de paramètres | ci-dessous |
| 2179 | RESERVE UNIT (§10.2.10) | |
| 2278 | SCAN (§15.2.5), liste de fenêtres de 0 o, contrôle 0x80 | bits 7-6 du contrôle réservés au fabricant (§7.2.7) |
| 2375, puis 17 fois | READ type 0x00 (image), qualificatif 0x0A0D, 2 091 744 o | « bloc suivant » (section 4) |
| 120250 | RELEASE UNIT (§10.2.9) | après l'état « fin de page » |

Les trois SEND sont identiques dans toutes les captures TWAIN (gris, couleur, noir et blanc, 150, 300, 600 dpi, recto-verso). Capture Tool (`1e-gris-300-recto`) envoie `00 78` (120) à 0x95 et 0x96, et en plus SEND 0xA2 (`00 0f`) et SEND 0x85 (128 o portant la date et le **numéro de série** : masqués par l'analyseur sans `--serie`).

### SET WINDOW (§15.2.7)

En-tête de 8 o (longueur du descripteur en octets 6-7 : 0x47 = 71), puis le descripteur de fenêtre. Trame 2067 :

| Champ (octets du descripteur) | Valeur | Lecture |
| --- | --- | --- |
| identifiant (0), auto (1) | 0, 0 | |
| résolution X, Y (2-5) | 300, 300 | 600 dpi : Y = 600, X reste 300 (`1e-gris-600-recto`) |
| origine X, Y (6-13) | 0, 0 | |
| largeur (14-17) | 10 368 | en 1/1200 po (unité par défaut, §15.3.3.1) : 8,64 po |
| longueur (18-21) | 16 800 | 14 po, soit 4 200 lignes à 300 dpi, la hauteur de l'image TWAIN |
| luminosité, seuil, contraste (22-24) | 0x80 | |
| composition (25) | 05 | **RVB multiniveau** (table 283) |
| bits par pixel (26) | 8 | |
| RIF, bourrage (29) | 0, 3 | tronqué à l'octet (table 284) |
| compression (32-33) | 0, 0 | aucune |
| vendeur (40-70) | 31 o | `ff 1d e0 ff 00 1e 60 10 68 10 00 00 64 00 64 00 64 00 00 00 00 0b 01 …` |

**Gris, couleur et noir et blanc envoient la même fenêtre, en couleur** (vérifié : fenêtres identiques octet pour octet dans 2a, `1e-couleur-300-recto`, `1e-nb-300-recto`, `1e-gris-150-recto` et `1e-couleur-300-recto-doc-couleur`). Le scanner scanne toujours en RVB ; la conversion en gris ou en noir et blanc se fait sur le PC (déduit). À 150 dpi aussi la fenêtre reste à 300 dpi : la réduction se fait également sur le PC (déduit).

Différences observées, en numérotant les octets vendeur de 0 à 30 (octet 40 + n du descripteur) :

- longueur : 17 340 (14,45 po) en recto-verso, 17 580 avec Capture Tool (1c, `1e-gris-300-recto`) ;
- résolution Y : 600 dans `1e-gris-600-recto` ;
- octets vendeur 7-8 : 0x1068 = 4 200, le nombre de lignes de 14 po à 300 dpi (déduit) ; 0x20D0 = 8 400 à 600 dpi, 0x21E0 = 8 672 en recto-verso, 0x2260 = 8 800 avec Capture Tool ;
- octet vendeur 17 : 0x00 ; 0x10 en recto-verso ; 0x80 dans les trois premières captures TWAIN en gris (`1e-gris-300-recto-twain`, `-2`, `-3`) ; 0x90 avec Capture Tool. Déduit : le bit 4 demande le recto-verso, et Capture Tool scannait donc en recto-verso (son volume, 60 blocs contre 32, va dans ce sens). Le bit 7 reste inexpliqué : 2a, en gris aussi, a 0x00 ;
- octet vendeur 22 : 0x01, sauf 0x00 là où l'octet 17 a son bit 7.

## 4. La boucle de lecture d'image

1. Dépôt de READ image (trame 2375).
2. Sondage `02 01 2` puis `02 02 2`, 24 o, six mots de 32 bits petit-boutistes. Le mot 0 est l'état : **0** pas prêt, **1** prêt, **3** fin de page. Dans 2a, 908 sondages avant le premier bloc, pendant que la feuille avance.
3. État 1 (réponse trame 52310) : mots 3 et 4 = 2 592 et 240, mot 5 = l'adresse du bloc, ici `0x0059AA00`.
4. Lectures 0xC3 : 9 de 65 536 o puis une de 32 256 o, de l'adresse annoncée en montant (trames 52325 à 52394). Total 622 080 o = 2 592 × 240.
5. Retour en 1. À l'état 3 (réponse trame 120209), RELEASE UNIT.

**Vérifié sur toutes les captures** (`banc/verif_blocs.py` sur les traces de l'analyseur) : chaque bloc annoncé est suivi de lectures 0xC3 contiguës depuis l'adresse annoncée, pour un total égal au produit des mots 3 et 4, soit 0 écart sur 17 blocs (2a) et 552 blocs (1c et 1e). Les facteurs valent 2 592 et 240 partout, 600 dpi compris.

Le sens de 2 592 et 240 est établi à l'étape 3b (section suivante) : 240 plans de 2 592 points, soit 80 lignes RVB par bloc.

## 5. Format des données d'image (étape 3b)

Établi en recollant les blocs (`banc/extrait_image.py`) et en les comparant aux BMP que le pilote TWAIN a produits pendant les mêmes captures (`banc/image_brute.py comparer`).

- Une ligne de balayage fait **7 776 o = 3 plans de 2 592 points**, dans l'ordre **rouge, vert, bleu**, 8 bits par échantillon, sans en-tête ni bourrage. Un bloc de 622 080 o porte 80 lignes.
- Vérifié par la structure : l'écart moyen entre deux octets distants de 7 776 (même plan, ligne suivante) vaut 4,7, contre 23 à 2 592 (même point, plan voisin) et 3,9 à 1 (point voisin) sur 2a. Les échantillons voisins d'un même plan se ressemblent, ceux de deux plans non : les plans ne sont pas entrelacés point par point.
- Vérifié par l'image : au décalage BMP(x, y) = brut(x + 4, y + 11), le plan 0 suit le rouge, le plan 1 le vert, le plan 2 le bleu du BMP couleur (corrélations 0,992, 0,999 et 0,998 sur la photo de `1e-couleur-300-recto-doc-couleur`, 0,999 à 1,000 sur `1e-couleur-300-recto`). Le même décalage vaut pour 2a.
- 2 592 points = 8,64 po à 300 ppp, la largeur de la fenêtre. Le pilote Brother en garde 2 548, à partir du 5e point, et saute les 11 premières lignes. Sous la feuille, il complète jusqu'à 4 200 lignes (14 po) avec un fond sombre.
- **Le gris du pilote Brother suit le plan vert** : corrélation 0,985 sur 2a, contre 0,957 pour le bleu, 0,814 pour le rouge et 0,974 pour la luminance 0,299 R + 0,587 V + 0,114 B.
- Les valeurs brutes sont sombres : le pilote leur applique sur le PC une courbe de tons (un brut de 144 donne environ 244). Seule la forme de l'image est comparable, pas les octets. La correction varie peu d'une colonne à l'autre (110 à 116 pour un même brut, par tranches de 128 colonnes sur les 1 280 premières, photo couleur) : l'essentiel est une courbe globale (déduit).
- À 600 dpi, la fenêtre ne double que la résolution Y : le scanner rend toujours 2 592 points par ligne, mais deux fois plus de lignes (65 blocs, 5 200 lignes). La largeur de 5 100 du BMP TWAIN est donc interpolée sur le PC (déduit).

## 6. Questions ouvertes

- Effet des SEND 0x83, 0x95, 0x96 : réglage en mémoire vive ou non volatile ? Capture Tool et TWAIN y envoient des valeurs différentes, chacun à chaque scan.
- Rôle de 0x08 et des READ 0xA0, 0xA1 (16 o, l'interrogation de fond de Button Manager) et 0x69 (128 o, porte le numéro de série).
- Sens du qualificatif 0x0A0D, de la longueur 2 091 744 du READ image (1 990 656 en recto-verso), du bit vendeur 0x80 de SCAN, des octets vendeur de la fenêtre.
- Sens de l'octet 1 (`07`) des CDB vendeur et des sondages `ff 03` à `ff 06`.
- Courbe de tons à appliquer pour retrouver la luminosité du pilote Brother, et rôle éventuel des lectures vendeur (0xA1, 0x69) dans cette correction.
