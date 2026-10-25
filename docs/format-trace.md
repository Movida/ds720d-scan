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
| trame | numéro de trame Wireshark | numéro d'ordre du transfert |
| temps | secondes depuis la première trame | secondes depuis le début du programme |
| adr | adresse USB de l'appareil | adresse lue du descripteur de l'appareil, sinon 0 |

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
| `ERREUR` | — | endpoint et code `USBD_STATUS_*` d'un transfert qui a échoué (ex. STALL) | WDK usb.h |
| `URB` | hôte | URB sans données, ex. `SYNC_RESET_PIPE_AND_CLEAR_STALL` | WDK usb.h |
| `INT-IN` | appareil → hôte | données d'un transfert d'interruption | USB 2.0 §5.7 |

Les lignes qui commencent par `|` détaillent la ligne précédente (descripteur, sense, INQUIRY, capacité).

Un opcode qui écrit sur le support ou le firmware (WRITE, FORMAT UNIT, WRITE BUFFER…) est marqué `!! ÉCRITURE`.
