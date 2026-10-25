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

**Résidu collé** (relecture de l'étape 3) : sous USBSTOR, des CSW 0xC5 à statut 0 annoncent `résidu=168` sur des lectures de 4 ou 16 o, entièrement reçues (1b : 226 fois, 1c : 6, `1e-gris-300-recto` : 827). C'est le résidu du MODE SENSE(6) de 192 o de Windows, qui n'en reçoit que 24 (`1e-gris-300-recto`, trame 14648) ; la commande 0xC5 suivante le répète (trame 14906). Le micrologiciel ne remet donc pas le résidu à zéro pour 0xC5 (déduit). Sous WinUSB, notre code n'envoie pas de MODE SENSE et n'a vu que des résidus nuls (2a, `3e-scan-2`). Un tel CSW, au résidu supérieur à la longueur demandée, n'est pas « significatif » selon BOT §6.3.2 : `src/bot.c` ferait une Reset Recovery. Choix gardé tant qu'aucune de nos commandes ne laisse de résidu.

## 2. 0xC5, un tunnel

### Sélecteurs

| Sélecteur | Sens, taille | Rôle |
| --- | --- | --- |
| `ff 02 00` | IN 4 o | rend `4e 4f 56 41`, « NOVA » : signature du contrôleur NovaTek (vérifié, trame 778) |
| `ff 03 00` à `ff 06 00` | IN 16 o | sondages d'état, intercalés entre tous les échanges. Réponse `10 00 00 00 01 00 00 00 0X 00…` : X vaut 0 pour `ff 03`, 1 pour `ff 04` à `ff 06` (dans 2a, 10 réponses de `ff 04` sur 6 432 ont X = 0 ; dans notre essai `3d-papier-sans`, 4 réponses de `ff 03` valent 1 et 2 de `ff 05` valent 0). Le pilote Brother n'en tient pas compte dans sa séquence. Rôle déduit : drapeaux d'occupation |
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

1. Sondages `ff 04`, `ff 03`, `ff 03`, `ff 05` (trames 781 à 800), puis le dépôt `02 03 00` (CBW 806, données 808), puis `ff 04`, `ff 06`.
2. Si la commande rend des données : mêmes sondages, `02 01 0` (trame 851), un `ff 04`, `02 02 0` (trame 863), puis `ff 04`, `ff 06`.
3. Mêmes sondages, `02 01 1` (trame 905), un `ff 04`, `02 02 1` (trame 917) : statut, puis `ff 04`, `ff 06`.

Cette chorégraphie se répète à l'identique pour chaque commande de 2a ; la signature `ff 02` est relue avant certaines (trames 772, 937, 1096, 1258, 1418). `src/tunnel.c` la reproduit (`tunnel_commande`).

La zone déposée commence par 10 o réservés au CDB emballé (un CDB de 6 o, groupe 0, y est suivi de 4 zéros), puis viennent les données éventuelles. Vérifié : dépôt de 12 o = 10 + 2 pour SEND 0x95 (trame 1755), 89 o = 10 + 0x4F pour SET WINDOW (trame 2067).

## 3. Les commandes emballées

Le premier octet de chaque dépôt est un opcode de la table 277 (commandes des scanners), sauf 0x08. Attention : dans ce jeu, 0x2A est **SEND**, pas WRITE(10). Aucune commande emballée n'écrit de support ni de firmware (pas de WRITE BUFFER, §8.2.17).

### Séquence de scan de 2a

| Données (trame) | Commande emballée | Lecture |
| --- | --- | --- |
| 808, 1130, 1450 | `08 00 00 00 02 00` | opcode absent de la table 277 (READ(6) chez les autres classes) ; rend 2 o : **présence d'une feuille**, `01 00` avec, `00 00` sans (déduit de 2a, `1e-sans-papier`, `1e-nb-300-recto`, `1e-gris-300-recto-verso` entre deux feuilles, et de notre essai `3d-papier-sans`) |
| 969, 1291, 1602 | READ type 0xA0 (vendeur), qualificatif 0x0A0D, 2 o | rend `01 00` |
| 1755 | SEND type 0x95 (vendeur), qualificatif 0x0001, 2 o : `00 00` | effet inconnu |
| 1859 | SEND type 0x96 (vendeur), qualificatif 0x0001, 2 o : `00 00` | effet inconnu |
| 1961 | SEND type 0x83 (vendeur), 18 o : neuf mots de 16 bits gros-boutistes, 0x0400 aux positions 0, 4 et 8, 0 ailleurs | effet inconnu ; une matrice 3 × 3 diagonale, matrice de couleur identité avec 0x0400 pour 1 (déduit) |
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
5. Retour en 1, après lecture du statut de READ (trames 52424 à 52436) et un nouveau dépôt de READ (trame 52478). À l'état 3 (réponse trame 120209), RELEASE UNIT, sans statut du dernier READ ; après RELEASE, `ff 04` répond « occupé » (octet 8 à 0) pendant environ 1,1 s, l'éjection de la feuille, et le pilote le relit toutes les 107 ms (trames 120255 à 120805).

Rejoué par `ds720d scan` à l'étape 3e (`src/ds720d.c`, `lire_page`) : même suite de commandes que 2a, mêmes délais (capture `3e-scan-2`).

**Vérifié sur toutes les captures** (`banc/verif_blocs.py` sur les traces de l'analyseur) : chaque bloc annoncé est suivi de lectures 0xC3 contiguës depuis l'adresse annoncée, pour un total égal au produit des mots 3 et 4, soit 0 écart sur 17 blocs (2a) et 552 blocs (1c et 1e). Les facteurs valent 2 592 et 240 partout, 600 dpi compris.

Le sens de 2 592 et 240 est établi à l'étape 3b (section suivante) : 240 plans de 2 592 points, soit 80 lignes RVB par bloc.

## 5. Format des données d'image (étape 3b)

Établi en recollant les blocs (`banc/extrait_image.py`) et en les comparant aux BMP que le pilote TWAIN a produits pendant les mêmes captures (`banc/image_brute.py comparer`).

- Une ligne de balayage fait **7 776 o = 3 plans de 2 592 points**, dans l'ordre **rouge, vert, bleu**, 8 bits par échantillon, sans en-tête ni bourrage. Un bloc de 622 080 o porte 80 lignes.
- Vérifié par la structure : l'écart moyen entre deux octets distants de 7 776 (même plan, ligne suivante) vaut 4,7, contre 23 à 2 592 (même point, plan voisin) et 3,9 à 1 (point voisin) sur 2a. Les échantillons voisins d'un même plan se ressemblent, ceux de deux plans non : les plans ne sont pas entrelacés point par point.
- Vérifié par l'image : au décalage BMP(x, y) = brut(x + 4, y + 11), le plan 0 suit le rouge, le plan 1 le vert, le plan 2 le bleu du BMP couleur (corrélations 0,992, 0,999 et 0,998 sur la photo de `1e-couleur-300-recto-doc-couleur`, 0,999 à 1,000 sur `1e-couleur-300-recto`). Le même décalage vaut pour 2a.
- 2 592 points = 8,64 po à 300 ppp, la largeur de la fenêtre. Le pilote Brother en garde 2 548, à partir du 5e point, et saute les 11 premières lignes. Sous la feuille, il complète jusqu'à 4 200 lignes (14 po) avec un fond sombre.
- **Le gris du pilote Brother suit le plan vert** : corrélation 0,985 sur 2a, contre 0,957 pour le bleu, 0,814 pour le rouge et 0,974 pour la luminance 0,299 R + 0,587 V + 0,114 B.
- Les valeurs brutes sont sombres : le pilote leur applique sur le PC une courbe de tons (détail dans « Rendu du pilote Brother » ci-dessous). Seule la forme de l'image est comparable, pas les octets. La correction varie peu d'une colonne à l'autre (110 à 116 pour un même brut, par tranches de 128 colonnes sur les 1 280 premières, photo couleur) : l'essentiel est une courbe globale (déduit).
- `out\convertir.exe` (étape 3f) écrit cette image en PGM (plan vert) ou en PNG gris ou couleur. Depuis l'étape 4d, il la rend d'abord comme le pilote Brother (`src/rendu.c` : recadrage, courbe de tons du gris, verso redressé, largeur doublée à 600 dpi) ; `--brut` garde les points tels quels. Écart moyen avec les BMP du pilote, mesuré par `banc/verif_png.py --bmp` : 2,0 niveaux en gris à 300 dpi, 1,7 au verso, 2,2 à 600 dpi ; 5,7 sur 2a, qui s'écarte de la courbe ; 20 à 30 en couleur, où l'on applique faute de mieux la courbe du gris à chaque plan.
- À 600 dpi, la fenêtre ne double que la résolution Y : le scanner rend toujours 2 592 points par ligne, mais deux fois plus de lignes (65 blocs, 5 200 lignes). **Vérifié à l'étape 4b** (`1e-gris-600-recto`, `image_brute.py comparer --colonnes-paires`) : le BMP de 5 100 points garde 2 550 points bruts, du 5e au 2 554e, et 22 lignes sautées (11 à 300 ppp) ; BMP(x, y) = brut(x / 2 + 4, y + 22), corrélation 0,996. Ses colonnes paires sont les points bruts (0,996 au plus proche voisin, contre 0,994 en moyenne de deux), ses colonnes impaires la moyenne des deux points voisins (0,997, contre 0,995 au plus proche voisin) : une **interpolation linéaire** au demi-point. Les écarts sont faibles mais vont tous dans ce sens (déduit pour la forme exacte du filtre). Le READ image vaut ici 2 091 744 o, comme en 2a (`28 00 00 00 0a 0d 1f ea e0 00`, trame 3033), et la fenêtre a l'octet vendeur 17 à 0x00 et 7-8 à 0x20D0 (trame 2718). Rejoué par `ds720d scan --ppp 600` à l'étape 4f (capture `4f-600`) : mêmes dépôts, brut identique à celui de la capture.

### Rendu du pilote Brother (étape 4c)

Mesuré avec `banc/courbe_tons.py` : chaque point du BMP du pilote est mis en face du point brut d'où il vient (décalages des étapes 3b, 4a et 4b), et l'on garde, pour chaque valeur brute, la médiane des valeurs rendues.

- **Recadrage** (vérifié) : le pilote garde 2 548 points à partir du 5e (colonnes brutes 4 à 2 551) et saute les 11 premières lignes à 300 ppp (22 à 600 ppp). Au verso, les mêmes colonnes, retournées, et 146 lignes sautées (section 6). Sous la feuille, il complète jusqu'à 14 po avec un fond sombre : c'est un remplissage du PC, pas des données du scanner.
- **Gris : une courbe fixe** (vérifié) : six faces scannées en gris (`1e-gris-300-recto-twain-3`, les quatre faces de `1e-gris-300-recto-verso`, `1e-gris-600-recto`) donnent la même courbe à ±1 près, à 300 comme à 600 ppp, au recto comme au verso ; l'écart interquartile reste de 1 à 3 niveaux, donc pas de correction notable par colonne. Elle est mesurée de 45 à 177 (au-delà, le scanner ne rend presque rien : le blanc du papier vaut environ 160 en brut) ; brut 40 → 91, 80 → 134, 120 → 169, 160 → 198.
- **C'est une loi de puissance** (déduit) : 255 · (v / 255)^0,554 colle à la mesure à 1,1 niveau près sur toute la plage mesurée, soit un gamma de 1,8 environ, sans réglage de noir ni de blanc. La courbe complète, mesurée puis prolongée par cette loi, est dans [courbe-gris.txt](courbe-gris.txt).
- **Exception** : 2a s'écarte de cette courbe dans les tons moyens (brut 80 → 123 au lieu de 134), mais pas au-dessus de 120. Cause inconnue (question ouverte).
- **Couleur : une correction qui dépend du document** (vérifié) : en couleur, la courbe est plus claire qu'en gris et diffère d'un plan et d'un document à l'autre (rouge 144 → 226 sur `1e-couleur-300-recto`, → 244 sur la photo de `1e-couleur-300-recto-doc-couleur`). Le pilote équilibre donc les couleurs selon le contenu (déduit) ; on ne sait pas comment.

## 6. Recto-verso (étape 4a)

Établi sur `1e-gris-300-recto-verso` (adresse 15, deux feuilles, quatre BMP du pilote TWAIN), avec `banc/extrait_image.py --recto-verso` et `banc/image_brute.py comparer --miroir`.

- **Commandes** : même suite que 2a pour chaque feuille (0x08 et READ 0xA0, trois SEND, SET WINDOW, RESERVE UNIT, SCAN, boucle de READ image, RELEASE UNIT), avec trois différences, toutes dans des dépôts observés : longueur de fenêtre 17 340 (14,45 po), octets vendeur 7-8 à 0x21E0 et 17 à 0x10 (trame 2500), READ image de 1 990 656 o (`28 00 00 00 0a 0d 1e 60 00 00`, trame 2811). Entre les deux feuilles, le pilote sonde 0x08 (`00 00`) jusqu'à la feuille suivante (`01 00`, trame 148346), puis rejoue toute la suite (trames 148455 à 149859).
- **Blocs** : 70 blocs par feuille, annoncés **par paires** : deux réponses « prêt » d'affilée, puis des tours « pas prêt » (trames 70212, 70446, puis 70676). Les mots 1 et 2 de la réponse valent 1 et 0 pour tous les blocs : **rien n'y dit la face**.
- **Face** : vérifié par l'image, les blocs de rang pair dans la page (0, 2, 4…) sont le **recto**, les impairs le **verso**. Recollés séparément, les pairs corrèlent à 0,996 et 0,997 avec les BMP 1 et 3, les impairs à 0,998 avec les BMP 2 et 4.
- **Miroir** : le verso arrive en miroir horizontal. Brut, il corrèle à -0,63 avec son BMP ; lu de droite à gauche, à 0,998. Un second capteur qui regarde l'autre face de la feuille la voit retournée de gauche à droite, mais défile dans le même sens (déduit). Pas de miroir vertical : le seul retournement horizontal donne déjà 0,998 (vérifié).
- **Décalages** : recto, BMP(x, y) = brut(x + 4, y + 11), comme en recto seul ; verso, BMP(x, y) = brut_miroir(x + 40, y + 146), soit les colonnes brutes 4 à 2 551 retournées : la même marge de 4 points, de l'autre côté. Identiques sur les deux feuilles.
- **Retard du verso** : 146 − 11 = 135 lignes, 0,45 po à 300 ppp. C'est exactement l'allongement de la fenêtre (14,45 po au lieu de 14) : le pilote scanne 0,45 po de plus pour que le verso, vu plus tard, couvre encore 14 po (déduit). L'écart entre les deux capteurs le long du trajet du papier serait donc de 0,45 po, environ 11 mm (déduit).
- Chaque face fait 35 blocs, 2 800 lignes (9,33 po) : la feuille était plus courte que la fenêtre ; le pilote complète jusqu'à 4 200 lignes avec son fond sombre, comme en recto.
- **Rejoué** par `ds720d scan --recto-verso` à l'étape 4e (capture `4e-rv`, deux feuilles) : mêmes dépôts que la capture, une face par fichier, identiques aux faces extraites de notre capture. Entre deux feuilles, le dépôt 0x08 une fois par seconde jusqu'à `01 00`, comme le pilote (trames 122627 à 148287), puis toute la séquence repart.

## 7. Questions ouvertes

- Effet des SEND 0x83, 0x95, 0x96 : réglage en mémoire vive ou non volatile ? Capture Tool et TWAIN y envoient des valeurs différentes, chacun à chaque scan.
- Rôle de 0x08 et des READ 0xA0, 0xA1 (16 o, l'interrogation de fond de Button Manager) et 0x69 (128 o, porte le numéro de série).
- Sens du qualificatif 0x0A0D, de la longueur 2 091 744 du READ image (1 990 656 en recto-verso), du bit vendeur 0x80 de SCAN, des octets vendeur de la fenêtre.
- Sens de l'octet 1 (`07`) des CDB vendeur et des sondages `ff 03` à `ff 06`.
- Rendu couleur du pilote Brother : correction dépendant du document, algorithme inconnu ; rôle éventuel des lectures vendeur (0xA1, 0x69). Écart de 2a à la courbe du gris.
