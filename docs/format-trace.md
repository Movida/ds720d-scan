# Format de trace commun

Une ligne par évènement USB. L'analyseur de captures (`banc/analyse_capture.py`) l'écrit à partir d'un pcap ; notre code C l'écrira pour chaque transfert qu'il émet. Les deux traces se comparent alors ligne à ligne.

```
# trame     temps (s)  adr  événement  détail
19223       28.912112   15  SETUP      a1 fe 00 00 00 00 01 00  GET_MAX_LUN wValue=0x0000 wIndex=0x0000 wLength=1 (IN)
19224       28.915087   15  CTRL-IN    1 o  00
                                    | plus haut LUN = 0
19225       28.915166   15  CBW        tag=0xA41D25B0 lun=0 IN 36 o  CDB[6]=12 00 00 00 24 00  INQUIRY
19228       28.915380   15  DATA-IN    36 o  00 80 05 02 20 00 00 00 42 72 6f 74 …
19230       28.915424   15  CSW        tag=0xA41D25B0 statut=0 (réussite) résidu=0
```

## Colonnes

| Colonne | Analyseur | Notre code C |
| --- | --- | --- |
| trame | numéro de trame Wireshark | numéro d'ordre de la ligne d'évènement (un SETUP et son CTRL-IN ont chacun le leur) |
| temps | secondes depuis la première trame | secondes depuis l'ouverture de la trace |
| adr | adresse USB de l'appareil | toujours 0 : WinUSB ne donne pas l'adresse |

## Évènements

| Évènement | Sens | Détail | Source |
| --- | --- | --- | --- |
| `SETUP` | hôte → appareil | les 8 octets du paquet SETUP, puis la requête décodée | USB 2.0 §9.3, tables 9-2, 9-4, 9-5 ; BOT §3.1-3.2 |
| `CTRL-OUT` | hôte → appareil | données de l'étape DATA d'un contrôle sortant | USB 2.0 §8.5.3 |
| `CTRL-IN` | appareil → hôte | données de l'étape DATA d'un contrôle entrant, descripteurs décodés en dessous | USB 2.0 §9.6 |
| `CBW` | hôte → appareil | tag, LUN, sens et longueur attendue, CDB, nom de l'opcode | BOT §5.1 ; SPC-4, SBC-3 |
| `DATA-OUT` | hôte → appareil | données envoyées pendant une commande sortante | BOT §5.1 (bmCBWFlags) |
| `DATA-IN` | appareil → hôte | données reçues pendant une commande entrante, réponse décodée en dessous si connue | BOT §5.1 ; SPC-4 |
| `CSW` | appareil → hôte | tag, statut, résidu | BOT §5.2 |
| `ERREUR` | — | endpoint et code `USBD_STATUS_*` d'un transfert qui a échoué (ex. STALL) ; dans notre code, le code Win32 rendu par WinUSB | WDK usb.h |
| `URB` | hôte | URB sans données, ex. `SYNC_RESET_PIPE_AND_CLEAR_STALL` | WDK usb.h |
| `INT-IN` | appareil → hôte | données d'un transfert d'interruption | USB 2.0 §5.7 |

Les lignes qui commencent par `|` détaillent la ligne précédente (descripteur, sense, INQUIRY, capacité). Depuis l'étape 3a, elles décodent aussi le protocole vendeur ([protocole.md](protocole.md)) : sous un CBW 0xC5 ou 0xC3, le sélecteur ou l'adresse ; sous un DATA-OUT de dépôt, la commande SCSI-2 emballée et, pour SET WINDOW, la fenêtre champ par champ ; sous un DATA-IN, la signature, l'état du bloc d'image, le statut ou l'identifiant. `src/trace.c` écrit le même texte depuis l'étape 3c pour les CBW 0xC5 et 0xC3 et les réponses, et depuis l'étape 3d pour les dépôts.

Un opcode qui écrit sur le support ou le firmware (WRITE, FORMAT UNIT, WRITE BUFFER…) est marqué `!! ÉCRITURE`.

## Côté C et comparaison

- `src/trace.c` écrit ce format pour notre code, avec le même texte que l'analyseur pour tout échange réussi : SETUP, CTRL-IN, CBW, DATA-IN, DATA-OUT, CSW, et les décodages de descripteurs, INQUIRY, sense, capacité et protocole vendeur.
- Écarts voulus : les lignes `ERREUR` donnent le code Win32 rendu par WinUSB (« contrôle » ou « bulk ») au lieu du code `USBD_STATUS_*` ; notre code n'écrit de ligne `URB` que pour le déblocage d'un endpoint (`SYNC_RESET_PIPE_AND_CLEAR_STALL`, que produit `WinUsb_ResetPipe`, étape 3c) ; le numéro de série masqué s'écrit « (numéro de série masqué) », sans la mention `--serie` propre à l'analyseur. Un chemin d'erreur ne peut donc pas concorder ligne à ligne.
- Écarts connus, sans effet sur le DS-720D : un octet NUL au milieu d'un texte INQUIRY ou STRING le coupe côté C, pas côté analyseur.
- `trace.c` masque aussi les réponses qui peuvent contenir le numéro de série (CLAUDE.md) : descripteur STRING d'index iSerialNumber, réponses 0xC5 de 128 et 165 o, page VPD 0x80 d'un INQUIRY. L'analyseur masque depuis l'étape 3a les mêmes réponses 0xC5 et les données de SEND 0x85 emballé (date et numéro de série envoyés par Capture Tool), sauf avec `--serie`.
- Captures de la VM (étape 6g) : VMware découpe côté hôte une phase de données de 64 Kio en plusieurs URB, que USBPcap voit séparément ; `analyse_capture.py --recoller` rassemble les données entrantes d'une même commande en une seule ligne DATA-IN, au numéro de trame du premier morceau, comme les voit le pilote. Sans effet sur une capture où chaque phase tient en un URB.
- `banc/compare_traces.py REFERENCE NOTRE` compare l'évènement et le détail de chaque ligne, sans les colonnes trame, temps et adresse. `--sans-trames A-B` écarte des trames de la référence, `--sans-notre A-B` des lignes de notre trace, `--sans-tags` ignore les tags des CBW et CSW, choisis librement par chaque hôte (BOT §5.1). Une trace vide de l'un ou l'autre côté fait échouer la comparaison.
- Banc d'essai sans scanner : `construire.cmd`, puis `out\essai_trace.exe TRACE.txt` rejoue l'énumération de `1b-enumeration.pcap` (trames 19191 à 19236), puis, depuis l'étape 3c, des échanges vendeur de 1b (20841 à 20961) et de 2a (905 à 922, 52307 à 52312, CBW 52325, 120206 à 120211) et les dix dépôts de 2a (806, 967, 1753, 1857, 1959, 2065, 2177, 2276, 2373, 120248, chacun jusqu'à son CSW). La référence est la concaténation des sorties de `analyse_capture.py … --adresse 15 --de A --a B` sur ces plages, dans cet ordre ; comparer avec `--sans-trames 19207-19213 --sans-notre 11-14 --sans-tags` (le numéro de série, remplacé par un faux dans l'essai ; les tags, choisis librement par l'essai).
