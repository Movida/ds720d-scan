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
| `3c-etat` | `ds720d etat` : INQUIRY puis la prise de contact du logiciel Brother par 0xC5, lecture seule (signature, sondages, identifiants), adresse 37 | 6 SETUP, 20 CBW, 20 CSW statut 0, 0 erreur ; « NOVA », 0x04F9, 0x60E2 ; concordance parfaite avec notre trace (105 lignes, décodage vendeur compris) et avec 1b (trames 19191 à 19206, 19223 à 19230, 20841 à 20961, tags ignorés) ; `contre_verif.py` : 0 écart | `2F7C71E0E62A321763FFB57917B4C7BB30DE6F574B3C11998FBA324C18314C82` |
| `3d-papier-sans` | `ds720d papier` sans feuille : prise de contact, puis signature et dépôt de 0x08 (présence du papier), adresse 37 ; premier essai, avant l'attente sur `ff 04` | 46 CBW, 46 CSW statut 0, 0 erreur ; 0x08 rend `00 00` : « pas de feuille ». Commandes identiques à 1b puis 2a (trames 772 à 934) ligne pour ligne ; seules diffèrent la réponse de 0x08 et six réponses de sondage ; `contre_verif.py` : 0 écart | `A06A0503F59C4D66C1751E22686C230BFADB08424C838545B70AE7A689281223` |
| `3d-papier-sans-2` | même essai avec le code commité (attente sur `ff 04` après chaque dépôt) | 46 CBW, 46 CSW statut 0, 0 erreur ; « pas de feuille » ; notre trace et la capture concordent (212 lignes) ; commandes identiques à 1b puis 2a ligne pour ligne, réponses mises à part (0x08 et trois sondages) ; `contre_verif.py` : 0 écart | `20DFFB06C7E177ABF20942B684302FB2FBF5765BF6685068597E222F47FB2F7D` |
| `3d-papier-avec` | `ds720d papier` avec une feuille dans le chargeur, adresse 37 | 175 CBW (dont 6 dépôts), 175 CSW statut 0, 0 erreur ; 0x08 et READ 0xA0 rendent `01 00` trois fois : « feuille engagée », feuille non entraînée ; notre trace et la capture concordent (742 lignes) ; commandes identiques à 1b puis 2a (trames 772 à 1726) ligne pour ligne (573 lignes) ; seules diffèrent trois réponses de sondage (`ff 03` à 1, `ff 05` à 0) ; `contre_verif.py` : 0 écart | `83DBA2C529D26F13DDB631E326BFB4847DE4462F4306DA90D4D0DB2B622C06CC` |
| `3e-scan` | `ds720d scan` : premier scan complet rejoué de 2a, adresse 37 | interrompu au 5e bloc : `USBD_STATUS_XACT_ERROR` (0xC0000011) sur une lecture 0xC3, puis `DEVICE_GONE` (0x80000300) ; le scanner a quitté le bus et notre Reset Recovery n'a plus trouvé d'appareil. Faux contact du câble, d'après David. Les 4 premiers blocs sont bons, et leurs délais ceux de 2a (un bloc toutes les 0,18 s) | `692F2C9AC75199B3CDB5704152799FB35F8D661D9FFBF673765C7054BA32D4E3` |
| `3e-scan-2` | `ds720d scan`, même essai après reprise des câbles, adresse 22 | 19 067 CBW, 19 067 CSW statut 0, 0 erreur ; 20 blocs, 12 441 600 o, 1 600 lignes ; notre trace et la capture concordent (78 399 lignes) ; `verif_blocs.py` : 0 écart sur 20 blocs ; le fichier brut de notre programme est identique, octet pour octet, aux blocs extraits de la capture ; mêmes commandes que 2a à partir de la trame 772, boucles repliées (tours « pas prêt », relectures de `ff 04`), à trois blocs près (feuille plus longue) ; `contre_verif.py` : 0 écart | `BF0212DC6A43901B6AA35DFA9B78B73A71B6A360F2861EBC7B44FAAC9C00C3DB` |
| `3g-scan` | `ds720d scan` après les corrections de la relecture de fond (RESERVE puis RELEASE même en erreur, Ctrl+C, plafond de blocs, lectures contrôlées par sélecteur et longueur), adresse 22 | 18 878 CSW statut 0, 0 erreur ; 20 blocs, 1 600 lignes ; notre trace et la capture concordent (77 622 lignes) ; `verif_blocs.py` : 0 écart ; brut identique aux blocs de la capture ; même suite de commandes que 2a, boucles repliées, à trois blocs près ; `contre_verif.py` : 0 écart | `647D82B3E6B047D1CB5EF56B308023F55986982EA5298BC9C45A52838A27CBC0` |
| `4e-rv` | `ds720d scan --recto-verso --feuilles 2` (accord écrit de David du 25/10 pour les fenêtres et le READ du recto-verso et du 600 dpi), deux feuilles (une carte, passée dans les deux sens), adresse 22 | 29 668 CBW, 29 668 CSW statut 0, 0 erreur ; 38 puis 46 blocs, alternés recto et verso, faces lisibles et le verso dans le bon sens après `convertir --verso` ; notre trace et la capture concordent (121 926 lignes) ; `verif_blocs.py` : 0 écart sur 84 blocs ; les quatre bruts de notre programme sont identiques, octet pour octet, aux faces extraites de la capture (`extrait_image.py --recto-verso`) ; suite des dépôts identique à `1e-gris-300-recto-verso` au nombre de tours près (longueur des feuilles, attente de la seconde), sans l'attente d'une troisième feuille du pilote TWAIN ; `contre_verif.py` : 0 écart | `3583C4152A2EB91BB80B6AFE76837B553D77EB088750E1BC9F57FB7C39D17A83` |
| `4f-600` | `ds720d scan --ppp 600`, une feuille (la carte manuscrite), adresse 22 | 0 erreur USBD, CSW tous à statut 0 ; 34 blocs, 2 720 lignes à 600 ppp ; notre trace et la capture concordent (122 433 lignes) ; `verif_blocs.py` : 0 écart ; brut identique, octet pour octet, aux blocs extraits de la capture ; suite des dépôts identique à `1e-gris-600-recto` au nombre de READ image près (feuille plus courte) ; page rendue par `convertir --ppp-y 600` en 5 100 × 2 698, proportions justes, `verif_png.py` conforme ; `contre_verif.py` : 0 écart | `A3E1E695A57104BBEF78089448A4B0E4A067DB08F8E283E42573DF70F0AA3746` |
| `4g-controle` | `ds720d scan --recto-verso --feuilles 2` après les corrections de la relecture de fond de l'étape 4 (signature avant chaque 0x08 de l'attente, premier 0x08 de la feuille suivante non répété), adresse 1 | 0 erreur USBD ; 36 puis 38 blocs ; notre trace et la capture concordent (123 544 lignes) ; `verif_blocs.py` : 0 écart sur 74 blocs ; quatre faces identiques à celles extraites de la capture ; entre les feuilles, signature puis 0x08 chaque seconde, puis READ 0xA0, 0x08, READ 0xA0, 0x08, READ 0xA0 et les SEND, comme `1e-gris-300-recto-verso` (trames 148250 à 149240) ; suite des dépôts identique à la référence au nombre de tours près ; `contre_verif.py` : 0 écart | `8E6E4A24607E8C5D441FE9D1AE72A06324227350CE92292EEC415A7D5EB2772D` |
| `5d-vm` | Scanner passé à la VM du banc noyau (docs/noyau.md, 5d) : énumération par l'invité sous USBSTOR, bascule WinUSB dans l'invité, puis `ds720d descripteurs`, `inquiry` et `etat` lancés **dans la VM**, adresse 20 | USBPcap sur Medabot voit tout le trafic de la VM ; Windows invité sous USBSTOR : TEST UNIT READY, READ CAPACITY, MODE SENSE, READ(10) (303 104 o lus), **aucune écriture**, STALL connus de 1b ; nos trois passages : concordance parfaite entre la capture et nos traces (18, 25 et 105 lignes), et entre nos traces de la VM et celles de Medabot (2d-trace-2, 2f-trace-2, 3c-trace) | `BA2A2DE890D52774AA1B6408B92CEEDF900D6215F89C33E2407D9B1D98237AD0` |

## Captures du pilote noyau (étape 6)

Même méthode, mais le scanner est passé à la VM du banc noyau, où c'est notre pilote `ds720d.sys` qui le tient ([pilote.md](pilote.md)). USBPcap sur Medabot voit le trafic de la VM (5d).

| Capture | Scénario | Résultat | SHA-256 |
| --- | --- | --- | --- |
| `6b-installation` | Squelette PnP de 6b, qui n'envoie rien : scanner passé à la VM (WinUSB), `installer.ps1 installer` (premier chargement de `ds720d.sys`), `cycle 5`, `retour` (USBSTOR, puis WinUSB par `bascule_winusb.exe`), `ds720d inquiry` sous WinUSB dans la VM, puis `installer` à nouveau ; adresse 30 | Tant que `ds720d` tient le scanner (138,0 à 251,4 s, puis à partir de 320,2 s), seul le concentrateur parle : GET_DESCRIPTOR DEVICE de 64 puis 18 o à chaque (ré)énumération, dont une par réactivation ; **aucun SET_CONFIGURATION, aucun CBW de notre fait**. Fenêtre USBSTOR du retour : TEST UNIT READY, READ CAPACITY, MODE SENSE, READ(10) (172 032 o), **aucune écriture**, STALL connus de 1b. Sous WinUSB, SET_CONFIGURATION 1 à chaque liaison ; `ds720d inquiry` : concordance parfaite entre la capture (trames 187686 à 187713) et notre trace (25 lignes, tags compris), et avec la trace de 5d | `91D4A36D09FA585D8F7E98BFA26F51D90545D45DDE2A4F46F2B39D89FDA6E976` |
| `6d-demarrage` | Pilote 6.4 prêt dans la VM ; capture interrompue par un plantage de la VM avant son installation (docs/pilote.md, 6d) | le scanner quitte la VM à 172,2 s (adresse 35, de nouveau sous WinUSB sur Medabot) quand VMware suspend la VM mise en veille par Windows ; aucun trafic de notre pilote | `3AEC522B464B85173B7ED794AEBA011C309C16C4B517F2C5D16AEF59800F8C87` |
| `6d-demarrage-2` | Installation du pilote 6.4 (premiers URB), 7 cycles puis plantage au 8e (WinDbg attaché), redémarrage de la VM, scanner repassé, 40 cycles sans débogueur ; adresses 41, puis 43 | Séquence du pilote (trames 411412 à 411429) : DEVICE 18 o, CONFIGURATION 9 puis 32 o, SET_CONFIGURATION 1, GET_MAX_LUN, réponse 0 ; **concordance parfaite avec 1b** (trames 19191 à 19224, 16 lignes) hors lectures STRING et SET_INTERFACE, que le pilote n'envoie pas ; à l'adresse 43, 41 démarrages complets ; deux ABORT_PIPE par pipe à chaque arrêt (déduit : le nôtre et celui de la pile) ; deux erreurs `USBD_STATUS_DEVICE_GONE` sur ABORT_PIPE quand VMware a rendu le scanner à Medabot | `BEDF7E538D3A79C360A775E077C3216194E4E2BAE4A37C889FA3B65373C4E882` |
| `6e-inquiry` | Pilote 6.5 (IOCTL, Bulk-Only noyau, barrière) installé par-dessus la 6.4.1, puis, dans la VM et sans élévation, `ds720dk descripteurs`, `lun`, `inquiry` et `essai_refus` ; adresse 43 | Démarrage du pilote comme en 6d ; nos trois passages : concordance parfaite entre la capture et les traces de `ds720dk.exe` (18, 21 et 25 lignes, tags compris), et avec celles de `ds720d.exe` sous WinUSB en 5d ; un seul CBW (INQUIRY, statut 0) ; **aucun TEST UNIT READY ni STRING 2** : la barrière du pilote les a refusés avant tout envoi | `574D7409A1DB89CA3A27625E74C4AF1168784A29E9A11EACF0DB54658C1D75DC` |
| `6f-tunnel` | Pilote 6.5 dans la VM : `ds720dk etat`, `papier` sans feuille, puis `papier` avec une feuille engagée ; adresse 43 | 3 INQUIRY, 238 commandes 0xC5 dont 7 dépôts, 241 CSW statut 0, 0 erreur ; concordance parfaite entre la capture et les traces de `ds720dk.exe` (105, 212 et 742 lignes, tags compris) ; commandes identiques à celles de WinUSB (5d, `3d-trace-sans-2`, `3d-trace-avec`), réponses de sondage près | `75A6BDD9B857CFFC9E7462CF4F2E81E43A267B59B446D2B2A6349ADBD88BCF9C` |
| `6g-recto` | `ds720dk scan`, recto 300 dpi, une feuille, par le pilote dans la VM ; adresse 43 | 16 blocs, 1 280 lignes ; avec `analyse_capture.py --recoller` (VMware découpe chaque lecture de 64 Kio en 36 864 + 28 672 o côté hôte) : concordance parfaite avec la trace (21 994 lignes, tags compris), 0 écart de blocs, brut identique à l'extraction ; dépôts identiques à 3g ; 26,3 Mo/s en lecture 0xC3 | `C160E9C029A414DA93B07135E698702D45C93157DC3553D274D79260A076B344` |
| `6g-rv` | `ds720dk scan --recto-verso --feuilles 2`, par le pilote dans la VM ; adresse 43 | 188 blocs, quatre faces de 3 760 lignes ; concordance parfaite avec la trace (53 374 lignes, `--recoller`), 0 écart, quatre faces identiques à l'extraction ; dépôts identiques à 4e | `B3430027E601921D460AE639995092763A62D827BD52276B6ABCC09B524EE33A` |
| `6g-600` | `ds720dk scan --ppp 600`, par le pilote dans la VM ; un premier essai « pas de feuille » (rien de scanné), puis le scan ; adresse 43 | 89 blocs, 7 120 lignes ; dernier passage : concordance parfaite avec la trace (70 765 lignes, `--recoller`), 0 écart, brut identique à l'extraction ; dépôts identiques à 4f | `8DF2C2E1950C2AA45518B0FF6D13C6E0DF87D19082D565775416B1DB364C5E18` |
