# Passer le scanner sous WinUSB, et revenir au pilote Brother

Pour que notre programme parle au scanner en transferts bruts (paquets SETUP, CBW, CSW écrits à la main), il faut que le pilote chargé pour lui soit **WinUSB** (`winusb.sys`), le pilote USB générique de Windows. Avant l'étape 2, c'est **USBSTOR** qui le tient : il le présente comme un disque (F:) et construit lui-même les CBW, ce qu'on veut justement faire nous-mêmes.

Un appareil USB n'a qu'un pilote de fonction à la fois. Sous WinUSB, F: disparaît et le logiciel Brother (TWAIN, Button Manager) ne voit plus le scanner. Rien n'est écrit dans le scanner : seul le choix du pilote change, côté Windows.

## Pourquoi le `winusb.inf` livré avec Windows

- Il est signé par Microsoft : aucune signature de pilote à contourner, aucun réglage de bcdedit.
- Pas d'INF maison : une INF à nous devrait être signée, ce qui n'a de sens qu'à l'étape noyau.
- Pas d'outil tiers comme Zadig (règle du projet), qui installe des INF générées par libwdi.
- Ce que ça coûte : le modèle générique « WinUsb Device » de `winusb.inf` ne correspond à aucun identifiant du scanner. Windows ne le choisira jamais seul : on le désigne à la main. Il n'enregistre pas non plus d'interface de périphérique propre (section `[WINUSB.NT]` sans `DeviceInterfaceGUIDs`) ; notre programme passe donc par l'interface USB générique (voir l'étape 2d).

## Aller : USBSTOR vers WinUSB (David, terminal administrateur)

1. Quitter le logiciel Brother s'il est ouvert (Capture Tool, Button Manager).
2. `construire.cmd`, puis, dans un terminal administrateur :
   ```
   C:\Users\morva\claude-chrome\ds720d-scan\out\bascule_winusb.exe --oui
   ```
   Sans `--oui`, et sans droits admin, le programme dit seulement ce qu'il ferait.

`src/bascule_winusb.c` ne vise que `USB\VID_04F9&PID_60E2` et refuse s'il en trouve zéro ou plusieurs. Il passe la classe d'installation du scanner à USBDevice, prend dans `winusb.inf` le modèle dont la section est `WINUSB` (et pas la variante de filtre `WINUSB_LowerFilter`, ni les modèles Billboard et ADB), puis l'installe avec `DiInstallDevice`.

### Pourquoi pas le Gestionnaire de périphériques

C'était le plan de départ (« Mettre à jour le pilote », « Choisir parmi une liste », « Disque fourni… » avec `winusb.inf`). Il échoue, essais du 25/10 :
- case « Afficher les matériels compatibles » cochée, Windows répond que le dossier « ne contient aucun pilote pour votre périphérique » : le modèle générique ne correspond à aucun identifiant du scanner ;
- case décochée, la liste ne montre que les pilotes de la classe du scanner, « USB » (contrôleurs de bus USB, `{36FC9E60-…}`, celle de `usbstor.inf`), alors que `winusb.inf` est de classe « USBDevice » (`{88BAE032-…}`). « Disque fourni… » ne propose rien non plus, et l'assistant se ferme sans rien installer (`setupapi.dev.log`).

`bascule_winusb.exe` le confirme à blanc : sans changer de classe, la liste des pilotes de `winusb.inf` pour le scanner est vide.

### Vérification (Claude, sans droits admin)

```
Get-PnpDevice -PresentOnly | Where-Object InstanceId -like 'USB\VID_04F9&PID_60E2*' | Get-PnpDeviceProperty DEVPKEY_Device_Service, DEVPKEY_Device_DriverInfPath, DEVPKEY_Device_DriverInfSection, DEVPKEY_Device_LowerFilters | Format-Table KeyName, Data
```

`Format-Table KeyName, Data` évite d'afficher l'identifiant d'instance, qui contient le numéro de série.

Attendu : service `WINUSB`, INF `winusb.inf`, section `WINUSB`, pas de filtre ; F: absent. Le scanner apparaît alors sous « Périphériques USB », nommé « DS-720D ».

Avant la bascule, le 25/10 : `USBSTOR`, `usbstor.inf`, section `USBSTOR_BULK.NT`, aucun filtre ; identifiants matériels `USB\VID_04F9&PID_60E2&REV_0100` et `USB\VID_04F9&PID_60E2`, identifiants compatibles dont `USB\Class_08&SubClass_06&Prot_50`.

## Retour : WinUSB vers USBSTOR (David, terminal administrateur)

```
pnputil /remove-device /deviceid "USB\VID_04F9&PID_60E2"
pnputil /scan-devices
```

`/remove-device` supprime le nœud du scanner et le pilote qui lui avait été attribué ; `/scan-devices` le fait redétecter. Windows reclasse alors les pilotes qui correspondent à ses identifiants : `usbstor.inf` répond à l'identifiant compatible `USB\Class_08&SubClass_06&Prot_50`, le modèle générique de WinUSB à aucun, donc USBSTOR revient. Débrancher et rebrancher le scanner devrait donner le même résultat que `/scan-devices`.

Vérification : service `USBSTOR`, F: revenu, et `py banc/twain_banc.py lister` voit la source TWAIN du DS-720D.

Après un retour (ou un aller qui suit un retour), débrancher et rebrancher le câble du scanner avant toute capture : USBPcap ne suit plus un appareil recréé par `pnputil` (voir docs/captures.md).

## Historique des bascules

| Date | Sens | Résultat |
| --- | --- | --- |
| 25/10/2026 | USBSTOR → WinUSB | réussi avec `bascule_winusb.exe --oui` : classe USBDevice, service WINUSB, section WINUSB, F: absent, disque WD intact |
| 25/10/2026 | WinUSB → USBSTOR | réussi avec les deux commandes `pnputil` : classe USB, service USBSTOR, section `USBSTOR_BULK.NT`, F: revenu, `twain_banc.py lister` lit les réglages de la source Brother |
| 25/10/2026 | USBSTOR → WinUSB | réussi à nouveau avec `bascule_winusb.exe --oui` ; le scanner reste sous WinUSB pour la suite de l'étape 2 |
| 25/10/2026 | rebranchement physique | toujours WinUSB : le choix de pilote est attaché à l'appareil (son numéro de série), pas à la session |
