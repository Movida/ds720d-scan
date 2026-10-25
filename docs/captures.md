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
- **À ajouter désormais : `-s 262144`.** La longueur de capture par défaut (65 535 o) coupe les blocs d'image de 65 536 o : avec les 27 o d'en-tête USBPcap, il manque 28 o de données par bloc. `py banc/analyse_capture.py <capture> --adresse N --resume` doit afficher « trames tronquées à la capture (snaplen) : 0 ».

### Capture pilotée par Claude (depuis 1e)

`banc/capture_admin.ps1` tourne avec les droits admin via une tâche planifiée que David a créée une fois. Claude la déclenche sans élévation : il écrit `demande.txt` (`nom=…`, `hub=1`, `duree=300`) dans le dossier des captures, lance `schtasks /run /tn ds720d-capture`, puis crée le fichier `stop` pour arrêter et l'efface ensuite. Le script refuse tout nom ou valeur hors des formats prévus, refuse un dossier ou une demande qui serait un lien (jonction, lien symbolique), n'écrase jamais une capture, n'arrête que ses propres USBPcapCMD et tient son journal dans `C:\ProgramData\ds720d\capture.log`, que Claude peut lire mais pas modifier.

Installation, une fois, par David dans un terminal administrateur. Le script est copié dans un dossier que seul un administrateur peut modifier : changer la version du dépôt n'a d'effet qu'après une nouvelle copie par David.

```
New-Item -ItemType Directory -Force C:\ProgramData\ds720d | Out-Null
icacls C:\ProgramData\ds720d /setowner "*S-1-5-32-544" /T
icacls C:\ProgramData\ds720d /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"
Copy-Item C:\Users\morva\claude-chrome\ds720d-scan\banc\capture_admin.ps1 C:\ProgramData\ds720d\
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\ProgramData\ds720d\capture_admin.ps1'
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
$reglages = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 20) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName ds720d-capture -Action $action -Principal $principal -Settings $reglages
```

(SID : `S-1-5-32-544` Administrateurs, `S-1-5-18` Système, `S-1-5-32-545` Utilisateurs, en lecture et exécution seulement.)

Mise à jour du script (après une modification dans le dépôt, relue par David) : `Copy-Item C:\Users\morva\claude-chrome\ds720d-scan\banc\capture_admin.ps1 C:\ProgramData\ds720d\ -Force`, dans un terminal administrateur.

Désinstallation : `Unregister-ScheduledTask ds720d-capture -Confirm:$false; Remove-Item -Recurse C:\ProgramData\ds720d`.

### Scan piloté par Claude (depuis 1e)

`banc/twain_banc.py` fait scanner le pilote Brother (source TWAIN 64 bits) sans Capture Tool, avec les réglages voulus, et encadre le scan d'une capture. TWAIN ne sert que côté référence (accord de David du 25/10). David glisse seulement la feuille.

```
py banc/twain_banc.py lister
py banc/twain_banc.py scanner --mode gris --dpi 300 --regle 0x1150=0 --regle 0x1151=0 --capture <nom>
```

- `--regle 0x1150=0 --regle 0x1151=0` coupe le recadrage et le redressement automatiques (codes TWAIN des capabilities AUTOMATICBORDERDETECTION et AUTOMATICDESKEW), faits par le PC après coup.
- Images en BMP dans `ds720d-captures\images\` (transfert TWAIN par fichier ; le transfert natif rend un handle tronqué à 32 bits).
- Brother Button Manager (`moon.exe`, systray) interroge le scanner par salves d'environ 50 commandes 0xC5, un cycle toutes les 0,52 s : ce trafic apparaît dans toutes les captures.

Analyse : `banc/analyse_capture.py` (trace au [format commun](format-trace.md)), vérifié par `banc/contre_verif.py` contre tshark.

Piège : Ctrl+C rend l'invite, mais USBPcapCMD continue dans un second processus, élevé. L'arrêter depuis un terminal **administrateur** (ou le Gestionnaire des tâches) avec `Get-Process USBPcapCMD | Stop-Process` ; hors admin, Windows répond « Accès refusé ». La dernière trame peut alors être tronquée.

## Registre

### 1b-enumeration.pcap (25/10/2026)

- SHA-256 : `41215D830CE9C88E6E8EF03D74EB16AC70EFB192312C9CCFC4C0981B51C80719`
- 47 555 112 o, 108 947 trames, environ 124 s. Contient aussi clavier, souris, casque et disque WD du même concentrateur.
- Scénario : scanner branché (adresse 2), débranché, rebranché (nouvelle adresse **15**), F: réapparu, arrêt.
- Repères relevés avec tshark, confirmés par l'analyseur en 1d (`contre_verif.py` : 0 écart à l'adresse 15 sur 5 247 CBW, 5 247 CSW, 10 SETUP et 8 erreurs ; 0 écart à l'adresse 2) :
  - Adresse 2, avant débranchement : commande SCSI **0xC5** (plage vendeur) répétée en boucle, 754 fois en 14,6 s.
  - Trame 19191 : premier GET_DESCRIPTOR (DEVICE) vers l'adresse 15 ; la réponse trame 19194 porte `idVendor 0x04F9`, `idProduct 0x60E2`.
  - Trames 19195 à 19213 : CONFIGURATION puis STRING ; la réponse trame 19204 est marquée « Malformed » par Wireshark, mais c'est normal : Windows demande d'abord 2 o (wLength=2) pour lire bLength, puis le descripteur entier (trame 19205).
  - Trames 19214 à 19224 : SET_CONFIGURATION, SET_INTERFACE, GET_MAX_LUN (BOT §3.2).
  - Trames 19225 à 19236 : deux INQUIRY (0x12) par CBW/CSW.
  - Trames 19237 à 19245 : READ FORMAT CAPACITIES (0x23), endpoint 0x81 en STALL, effacé par `URB_FUNCTION_SYNC_RESET_PIPE_AND_CLEAR_STALL`, CSW en échec ; suivi d'un REQUEST SENSE (0x03), trame 19246.
  - Ensuite, adresse 15 : 0xC5 encore, 5 034 fois en 95 s.

### 1c-scan-gris-300.pcap (25/10/2026)

- SHA-256 : `CD45A4B4FEBEF08F54EA839F76331C1F9B1F6AB6ABA96E0ACC3E5588C8D42255`
- 63 680 924 o, 164 116 trames, environ 54 s. Scanner à l'adresse 15 du début à la fin.
- Scénario : Capture Tool, une page sans données personnelles, gris, 300 dpi, recto.
- **Défaut** : capturée avec la longueur par défaut, 666 blocs d'image de 65 536 o y sont tronqués de 28 o. Bonne pour étudier le protocole, inutilisable pour reconstruire l'image.
- Repères relevés avec tshark, confirmés par l'analyseur en 1d (`contre_verif.py` : 0 écart sur 22 175 CBW et 22 175 CSW) :
  - Aucune commande d'écriture (pas de WRITE ni de FORMAT) : le protocole ne passe pas par des secteurs du faux disque.
  - **0xC5** (vendeur), 21 370 CBW. Surtout en lecture (bit 7 de `bmCBWFlags` à 1) de 16 o (16 792) et 24 o (3 970) ; aussi 161 en écriture de 10 o, la première trame 78, puis toutes les 0,52 s environ  ; en écriture aussi, 2 de 12 o, 1 de 28 o et 1 de 89 o.
  - **0xC3** (vendeur), 740 CBW en lecture : 666 de 65 536 o et 74 de 32 256 o, soit 46 033 920 o. Première trame 82543 (10,66 s), dernière trame 128938 (17,43 s). Très probablement les données d'image ; le volume dépasse ce qu'attend une page A4 en gris 300 dpi (environ 8,7 Mo), à expliquer.
  - Commandes standard de Windows sur le faux disque : TEST UNIT READY (56), READ CAPACITY(10) (3), MODE SENSE(6) (2), READ(10) des secteurs 0, 0x20 et 0x23 (FAT et répertoire).
  - Pistes, **déduites et non vérifiées**, pour l'étape 3 : tous les CDB vendeur font 16 o et commencent par `xx 07`, puis les octets 2 à 5 ressemblent à une adresse et les octets 6 à 9 à la longueur de données, en gros-boutiste. Pour 0xC3, la lecture de 0x7E00 o à `0x01597600` est suivie d'une lecture à `0x0159F400`, soit 0x7E00 plus loin  ; dans cette capture (Capture Tool), chaque CDB 0xC3 est lu deux fois. Pour 0xC5, l'adresse vaut 0 et les octets 10 à 12 changent (`ff 04 00`, `02 01 02`, `02 02 02`…), comme un numéro de registre ou de canal. **Confirmé et détaillé à l'étape 3a** dans [protocole.md](protocole.md).

### Série 1e (25/10/2026)

Toutes avec `-s 262144` : 0 trame tronquée. Scanner à l'adresse 15. « Pilotée » : capture et scan lancés par Claude (`twain_banc.py`, recadrage et redressement coupés). Images BMP dans `ds720d-captures\images\`.

| Capture | Scénario | Octets lus par 0xC3 | SHA-256 |
| --- | --- | --- | --- |
| `1e-gris-300-recto` | Capture Tool, lancé par David | 37 324 800 | `4472092D60228219429C2A1B306963D5CDD4020BE8A4230B6E60BC90B77AD51E` |
| `1e-insertion-feuille` | feuille approchée, sans scan | — | `A5080575ADBCADBF4EE08FA617B9E6F7C303EEFC1FF9542E1D7F48327DE750B7` |
| `1e-retrait-insertion` | feuille retirée puis remise, sans scan | — | `13146A8CDA01393F8065DF630FEFA8276C898A315E5F53A7F27D13DF32B7A297` |
| `1e-insertion-2` | feuille sortie complètement puis remise, sans scan | — | `7860D96C4735CA0A1D888B5EF8F3F42C6500A7F313E13AE9DDEC81AD31D83125` |
| `1e-gris-300-recto-twain` | pilotée, gris 300 (image perdue) | 19 906 560 | `53A3EE74BFE218A77DA6F52A4BDAAEEEA7DC9C535D04768783880197D3B58B04` |
| `1e-gris-300-recto-twain-2` | pilotée, gris 300 (image perdue) | 20 528 640 | `1A2E82D4693B7C3246390AA3559F3CEB673109A234184ABE4FAB6DED12A0AD3F` |
| `1e-gris-300-recto-twain-3` | pilotée, gris 300, image 2548 × 4200 | 19 906 560 | `4D0A8A0FFDF1853EAB1190057919582BCE96EF14936294E74C88FDD3A2BFACDE` |
| `1e-couleur-300-recto` | pilotée, couleur 300, image 2548 × 4200 × 24 bits | 19 906 560 | `2E7A4ECB9CC698ACAC1F13C5C728BDD0CFA3B4AD115ADC78D331C034418396A0` |
| `1e-gris-300-recto-verso` | pilotée, gris 300 recto-verso, 2 feuilles, 4 images | 87 091 200 | `A0994D257E92228E05F2A7D2B31D373AC41FA9D348821428301B897C59A03204` |
| `1e-sans-papier` | pilotée, délai 0x925A à 1 s, « Aucun document » | — | `FFAE4A1C159939AAC3A474AD75B9E3D18D60DEB3B4B583B2EF1A922DAFC8ED78` |
| `1e-gris-600-recto` | pilotée, gris 600, image 5100 × 8400 | 40 435 200 | `AABA5971843C631CBF3A4ED06B4F2E8DA0F5766DD82E7EB356313261672D69BA` |
| `1e-nb-300-recto` | pilotée, noir et blanc 300, d'abord « Aucun document » puis scan | 19 906 560 | `9A3D8E41A3759D480ADB4810644C5F0827A2B52541C7C44F7A8B88A357AB8CDC` |
| `1e-gris-150-recto` | pilotée, gris 150, image 1272 × 2100 | 19 906 560 | `6A063FFAD07C2A4D09256B522F40E26E455B996036F2892A4C293A033D4091C0` |
| `1e-couleur-300-recto-doc-couleur` | pilotée, couleur 300, photo plus courte qu'un A4 (dinosaure vert, cœur rouge, ciel bleu) | 12 441 600 | `9FDFAA6C3EAB0772A19675B2F3A6558343F9CF2BCFC4CFE8ACCA590A19418E74` |

Constats, à approfondir à l'étape 3 :
- **Le volume lu par 0xC3 ne dépend ni du mode ni de la résolution jusqu'à 300 dpi** : 320 lectures, toutes à des adresses différentes, soit 19 906 560 o en gris, couleur et noir et blanc à 300 dpi comme en gris à 150 dpi. Le scanner enverrait toujours la même chose, et le pilote Brother ferait la réduction, le gris ou le noir et blanc sur le PC (déduction).
- Il suit en revanche la longueur de la feuille : 12 441 600 o pour la photo plus courte qu'un A4, alors que l'image rendue garde 2548 × 4200.
- À 600 dpi, le volume ne fait que doubler (40 435 200 o, 650 lectures), alors que l'image a quatre fois plus de pixels.
- Les adresses lues reviennent : 370 adresses distinctes au plus (23 016 960 o) dans toutes les captures, et au-delà (600 dpi, recto-verso) les mêmes adresses sont relues. Piste : une mémoire tampon circulaire dans le scanner. Dans `1c` (Capture Tool), chaque bloc est en plus lu deux fois.
- Écritures 0xC5 d'effet inconnu, à comprendre avant tout rejeu : 10 o (le cycle de Button Manager), 12 o, 28 o, 89 o et, dans `1e-gris-300-recto`, 2 de 138 o.
- Ni l'approche, ni le retrait, ni la remise d'une feuille ne changent la moindre réponse aux interrogations de Button Manager. L'évènement `81 03 00 00 00 00 01 00`, vu une fois dans `1e-gris-300-recto` juste avant le scan, reste inexpliqué.
- Pilote TWAIN Brother : il ignore `CAP_XFERCOUNT` et attend une feuille de plus après chaque feuille ; le réglage `0x925A` est ce délai en secondes (déduit : à 1 s, « Aucun document » immédiat).
- `contre_verif.py` sur `1e-couleur-300-recto` : 0 écart sur 29 155 CBW et 29 155 CSW.

### 2a-gris-300-recto-sans-bm.pcap (25/10/2026)

- SHA-256 : `986EA4A3B19FE3686036C091BDCAFE79917CE096CC248A0C4E98E19A6B973CCB`
- 20 575 976 o, 0 trame tronquée, scanner à l'adresse 15. Dernière capture avant la bascule sous WinUSB.
- Scénario : pilotée, gris 300 recto, recadrage et redressement coupés, **Brother Button Manager arrêté** (`moon.exe`). Image 2548 × 4200.
- Résultat : **aucune interrogation de fond**. Avant le scan et après, le scanner ne reçoit que des TEST UNIT READY de Windows, environ une par seconde ; le service `Mobile_Series` n'interroge pas le scanner. Les 19 492 commandes de la capture viennent donc toutes du pilote TWAIN : c'est la séquence de scan seule, la référence de l'étape 3.
- Déroulé : premier 0xC5 à 1,71 s, rafale d'écritures 0xC5 de 10, 12, 28 et 89 o entre 1,72 et 1,87 s, lectures 0xC3 de 3,0 à 6,9 s, plus rien après 8,8 s.
- 0xC3 : 170 lectures (153 de 65 536 o, 17 de 32 256 o), 10 575 360 o, environ la moitié des autres scans gris 300 (19 906 560 o). Expliqué par David : feuille plus petite qu'un A4, passée dans l'autre sens. Le volume suit la longueur de feuille qui passe, comme pour la photo de `1e-couleur-300-recto-doc-couleur`.
- Piste, **déduite et non vérifiée**, pour l'étape 3 : le premier octet des données écrites par 0xC5 ressemble à un opcode SCSI emballé dans la commande vendeur (0x08, 0x16, 0x1B, 0x24, 0x28, 0x2A). Le bloc de 89 o commence par 0x24, et contient `01 2c 01 2c`, soit 300 × 300 en gros-boutiste : il pourrait s'agir d'un SET WINDOW, la commande de réglage de fenêtre des scanners SCSI (SCSI-2, chapitre « Scanner devices »). 0xC5 servirait de tunnel vers un jeu de commandes scanner. **Confirmé à l'étape 3a**, détail dans [protocole.md](protocole.md).

## Captures de notre code (étape 2)

Même méthode (tâche planifiée, `-s 262144`), mais c'est notre programme qui parle au scanner, sous WinUSB. Elles servent au contrôle croisé : notre trace, la capture de notre passage et la référence doivent concorder (`banc/compare_traces.py`). Les traces texte (`--trace`, et la sortie de l'analyseur sur chaque capture) sont rangées dans `C:\Users\morva\ds720d-captures\traces\`, hors du dépôt comme les captures.

**Piège** : après une bascule par `pnputil /remove-device` puis `/scan-devices`, USBPcap ne voit plus le scanner (`2d-descripteurs.pcap`, 25/10 : aucune trame du scanner alors que le programme a bien échangé avec lui). Un débranchement physique du câble suffit à le rattacher. Le scanner garde alors WinUSB.

| Capture | Scénario | Résultat | SHA-256 |
| --- | --- | --- | --- |
| `2d-descripteurs` | `ds720d descripteurs`, juste après la bascule | aucune trame du scanner (piège ci-dessus) | `F08FAB1899BB16464C557A0EB3AEF87A0EAF61D78FBC13ADA76497B167972173` |
| `2d-descripteurs-2` | `ds720d descripteurs`, après rebranchement (adresse 31) | 5 SETUP, 0 erreur ; concordance parfaite avec notre trace et avec 1b (trames 19191 à 19206) | `28194EAA734C05FB82D50CD83751229E5E20E169E6EBD5BD287369315BC8FD7F` |
| `2e-lun` | `ds720d lun` : descripteurs puis GET_MAX_LUN | 6 SETUP, 0 erreur, plus haut LUN 0 ; concordance parfaite avec notre trace et avec 1b (trames 19191 à 19206, 19223, 19224) | `ABC4ADD2AC07943AA70B29BC00C688967FDB7543EF9BD5C9805685E4BDC299A7` |
| `2f-inquiry` | `ds720d inquiry` : descripteurs, GET_MAX_LUN, puis INQUIRY dans un CBW fait main (tag 1) | 6 SETUP, 1 CBW, 1 CSW statut 0, 0 erreur ; concordance parfaite avec notre trace et avec 1b (trames 19191 à 19206, 19223 à 19230, tags ignorés) ; `contre_verif.py` : 0 écart | `225CC0D46BBDCCF5BD1F0E3AE946CA658FC238F002D9FD37F968877465488C07` |
| `2f-inquiry-2` | `ds720d inquiry` après les corrections de la relecture de fond (tag de départ variable, adresse 117) | 6 SETUP, 1 CBW, 1 CSW statut 0, 0 erreur ; concordance parfaite avec notre trace et avec 1b (tags ignorés) | `17EBBF24300B40848E788D0D00997345E0700FBD6AC0C30454448DE60B98FA84` |
