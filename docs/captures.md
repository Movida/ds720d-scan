# Captures de référence

Les fichiers restent **hors du dépôt**, dans `C:\Users\morva\ds720d-captures\` (ils peuvent contenir des images de documents et le trafic d'autres appareils). Ce registre en garde l'identité (SHA-256) pour que les numéros de trame cités dans le code restent vérifiables.

## Méthode

USBPcapCMD est lancé par David dans un **Terminal (Admin)** (l'ouverture de `\\.\USBPcapN` demande les droits administrateur) :

```
& "C:\Program Files\USBPcap\USBPcapCMD.exe" -d \\.\USBPcap1 -A -b 8388608 -o C:\Users\morva\ds720d-captures\<nom>.pcap
```

- `-d \\.\USBPcap1` : concentrateur racine où est branché le scanner (vu avec `--extcap-interface \\.\USBPcap1 --extcap-config`).
- `-A` : tous les appareils du concentrateur. Ce USBPcapCMD n'a pas d'option « nouveaux appareils », et le scanner change d'adresse quand on le rebranche ; un filtre `--devices` le perdrait.
- `-b 8388608` : tampon de 8 Mo, pour ne pas perdre de trames pendant un scan.
- Format de sortie : pcap classique, type de lien USBPcap.

Piège : Ctrl+C rend l'invite, mais USBPcapCMD continue dans un second processus, élevé. L'arrêter depuis un terminal **administrateur** (ou le Gestionnaire des tâches) avec `Get-Process USBPcapCMD | Stop-Process` ; hors admin, Windows répond « Accès refusé ». La dernière trame peut alors être tronquée.

## Registre

### 1b-enumeration.pcap (25/10/2026)

- SHA-256 : `41215D830CE9C88E6E8EF03D74EB16AC70EFB192312C9CCFC4C0981B51C80719`
- 47 555 112 o, 108 947 trames, environ 124 s. Contient aussi clavier, souris, casque et disque WD du même concentrateur.
- Scénario : scanner branché (adresse 2), débranché, rebranché (nouvelle adresse **15**), F: réapparu, arrêt.
- Repères relevés avec tshark (contre-vérification, à confirmer par notre analyseur en 1d) :
  - Adresse 2, avant débranchement : commande SCSI **0xC5** (plage vendeur) répétée en boucle, 754 fois en 14,6 s.
  - Trame 19191 : premier GET_DESCRIPTOR (DEVICE) vers l'adresse 15 ; la réponse trame 19194 porte `idVendor 0x04F9`, `idProduct 0x60E2`.
  - Trames 19195 à 19213 : CONFIGURATION puis STRING ; la réponse trame 19204 est marquée « Malformed » par Wireshark, à examiner.
  - Trames 19214 à 19224 : SET_CONFIGURATION, SET_INTERFACE, GET_MAX_LUN (BOT §3.2).
  - Trames 19225 à 19236 : deux INQUIRY (0x12) par CBW/CSW.
  - Trames 19237 à 19245 : READ FORMAT CAPACITIES (0x23), endpoint 0x81 en STALL, effacé par `URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL`, CSW en échec ; suivi d'un REQUEST SENSE (0x03), trame 19246.
  - Ensuite, adresse 15 : 0xC5 encore, 5 034 fois en 95 s.

### 1c-scan-gris-300.pcap (25/10/2026)

- SHA-256 : `CD45A4B4FEBEF08F54EA839F76331C1F9B1F6AB6ABA96E0ACC3E5588C8D42255`
- 63 680 924 o, 164 116 trames, environ 54 s. Scanner à l'adresse 15 du début à la fin.
- Scénario : Capture Tool, une page sans données personnelles, gris, 300 dpi, recto.
- Repères relevés avec tshark (à confirmer par notre analyseur en 1d) :
  - Aucune commande d'écriture (pas de WRITE ni de FORMAT) : le protocole ne passe pas par des secteurs du faux disque.
  - **0xC5** (vendeur), 21 370 CBW. Surtout en lecture (bit 7 de `bmCBWFlags` à 1) de 16 o (16 792) et 24 o (3 970) ; aussi 161 en écriture de 10 o, la première trame 78, puis toutes les 0,52 s environ ; 2 en écriture de 12 o.
  - **0xC3** (vendeur), 740 CBW en lecture : 666 de 65 536 o et 74 de 32 256 o, soit 46 033 920 o. Première trame 82543 (10,66 s), dernière trame 128938 (17,43 s). Très probablement les données d'image ; le volume dépasse ce qu'attend une page A4 en gris 300 dpi (environ 8,7 Mo), à expliquer.
  - Commandes standard de Windows sur le faux disque : TEST UNIT READY (56), READ CAPACITY(10) (3), MODE SENSE(6) (2), READ(10) des secteurs 0, 0x20 et 0x23 (FAT et répertoire).
