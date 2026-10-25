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

Piège : Ctrl+C rend l'invite, mais USBPcapCMD continue dans un second processus. L'arrêter avec `Stop-Process -Id <pid>` (pid donné par `Get-Process USBPcapCMD`). La dernière trame peut alors être tronquée.

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
