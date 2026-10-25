# Banc noyau : VM, passage USB, débogage, test-signing

Préparé à l'étape 5 (25/10/2026) pour l'étape 6 (pilote KMDF). Règles dans [CLAUDE.md](../CLAUDE.md) ; tout ce qui touche au noyau, à bcdedit, à Secure Boot ou à la signature des pilotes demande l'accord écrit de David.

## Principe

Le pilote ne se charge **que dans une machine virtuelle** Windows, jamais sur Medabot. Le scanner est passé à la VM par USB, le débogueur noyau tourne sur Medabot et se relie à la VM par le réseau virtuel.

```
Medabot (hôte, intact)                       VM Windows 11 (invité, jetable)
  WinDbg  ◄──── KDNET (UDP, réseau hôte-VM) ────  noyau en mode débogage
  WDK + nmake : construit et signe le pilote ──►  test-signing, Secure Boot coupé
  VMware : arbitrage USB  ──── scanner DS-720D ──►  xHCI virtuel ─► notre pilote KMDF
```

Sur Medabot, **ni bcdedit, ni Secure Boot, ni VBS/HVCI ne changent**. Avec l'intégrité de la mémoire (HVCI) active, un pilote signé en test ne se chargerait pas de toute façon. Un écran bleu tue la VM, pas le PC ; un instantané de la VM la remet en état.

Pourquoi pas sur Medabot : il faudrait couper Secure Boot et HVCI sur le PC principal (sauvegardes, WSL, Docker), et le débogage noyau exige de toute façon une seconde machine.

## Inventaire de départ (25/10, lecture seule, sans élévation)

| Élément | Constat |
| --- | --- |
| Windows | 11 Professionnel 26H2, build 26300, 64 bits |
| Matériel | MSI MS-7C56, Ryzen 5 5600X (6 cœurs, 12 threads), 32 Go |
| Virtualisation | Active dans le firmware ; hyperviseur Microsoft déjà actif (WSL 2) ; Hyper-V complet non installé |
| Sécurité | UEFI, Secure Boot actif, VBS et HVCI actifs |
| Outils | SDK 10.0.26100 seul : ni WDK, ni WinDbg, ni Debugging Tools ; aucun hyperviseur tiers |
| Disque | D: 381 Go libres (la VM y sera) |

## Choix

### Hyperviseur : VMware Workstation Pro

| Option | Passage USB du scanner | Avec l'hyperviseur Windows actif | Verdict |
| --- | --- | --- | --- |
| **VMware Workstation Pro** (gratuit en usage personnel) | Périphérique brut : l'invité le voit derrière un xHCI virtuel et le lie comme un vrai appareil | Tourne au-dessus de Windows Hypervisor Platform, sans couper VBS ni WSL | **Retenu** |
| Hyper-V | Impossible sur Windows client : DDA est réservé à Windows Server (et passe un contrôleur PCIe entier) ; la session améliorée ne redirige que des classes via RDP | Natif | Écarté |
| Hyper-V + USB/IP (usbipd-win, usbip-win2) | Derrière un contrôleur virtuel logiciel, lui-même pilote noyau tiers signé en test | Natif | Écarté : une couche noyau tierce entre notre code et les URB |
| VirtualBox | Oui | Mode dégradé « NEM », Windows 11 invité lent et instable | Écarté |

À vérifier en 5d (déduit de la doc VMware, pas encore observé) : le passage USB fonctionne au-dessus de l'hyperviseur Windows.

### Débogage noyau : KDNET, série en secours

- **KDNET** (UDP) : méthode recommandée par Microsoft, rapide (symboles, vidages, traces). La carte émulée par VMware, Intel 82574L (« e1000e »), figure dans la liste des cartes prises en charge par KDNET. Coût : une règle de pare-feu entrante sur Medabot, limitée au réseau hôte-VM.
- **Secours** : port série virtuel sur tube nommé, sans carte réseau ni pare-feu, mais à 115 200 bauds (symboles très lents).
- Écarté : le débogage local sur Medabot, en lecture seule (ni point d'arrêt ni reprise après plantage).
- Débogueur : WinDbg de Microsoft (version actuelle), sur Medabot.

### Windows de la VM

Windows 11 Enterprise Évaluation (ISO gratuite du centre d'évaluation Microsoft, 90 jours, réarmable ; les instantanés évitent de réinstaller). Version publique stable, pas l'Insider de Medabot, pour viser un Windows courant. Choix par défaut retenu le 25/10, David ne l'ayant pas contesté avec le « go ».

Réglages : UEFI et TPM virtuel (exigés par l'installation de Windows 11), puis **Secure Boot coupé dans le firmware de la VM** (sinon le test-signing est refusé), intégrité de la mémoire coupée dans l'invité ; 4 processeurs virtuels, 8 Go de RAM, disque de 80 Go sur D:, carte réseau e1000e sur le réseau hôte seul (« host-only »).

### WDK : construction toujours à la main

WDK **10.0.26100**, la version du SDK déjà installé. Le pilote se construira par notre `Makefile` nmake : `cl` avec `/kernel`, `link /DRIVER`, sans projet MSBuild généré, pour voir chaque option et sa raison. Le WDK apporte les en-têtes `km` et `wdf`, les bibliothèques KMDF, `stampinf`, `inf2cat`, `infverif` et `tracewpp`. Pourquoi pas l'EWDK (ISO autonome) : il embarque un second compilateur alors que les Build Tools 2022 sont déjà là.

### Le faux disque dans la VM

Au premier branchement, le Windows invité lierait le scanner à USBSTOR et monterait le volume FAT12. Règle « jamais écrire sur F: » : **montage automatique coupé dans la VM (`mountvol /N`) avant le premier passage du scanner**, puis bascule sous WinUSB par `bascule_winusb.exe`, comme à l'étape 2.

## Sous-étapes

| Sous-étape | Contenu | Qui | Accord écrit de David |
| --- | --- | --- | --- |
| 5a | Ce document, passation et historique | Claude | Non |
| 5b | Point de restauration de Medabot, sauvegarde Kopia récente vérifiée ; installation de VMware Workstation Pro, WinDbg, WDK 10.0.26100 et Debugging Tools for Windows (pour `kdnet.exe`) ; inventaire relu | David, Claude vérifie | **Oui** (binaires tiers) |
| 5c | Création de la VM, installation de Windows, Secure Boot de la VM coupé, instantané `windows-propre` | David, Claude guide | **Oui** (Secure Boot de la VM) |
| 5d | Montage automatique coupé, scanner passé à la VM, `bascule_winusb.exe`, puis `ds720d descripteurs`, `inquiry`, `etat` dans la VM ; trace comparée à la référence ; essai d'USBPcap côté hôte | Claude, David pour l'admin dans la VM | Non (commandes déjà autorisées) |
| 5e | `bcdedit /debug on` et `/dbgsettings net` dans la VM, règle de pare-feu sur Medabot, WinDbg attaché, arrêt et reprise, instantané `debug-pret` | David, Claude guide et vérifie | **Oui** (bcdedit de la VM, pare-feu de Medabot) |
| 5f | Test-signing dans la VM, certificat de test, pilote minimal fait main (`DriverEntry`, un `DbgPrint`, déchargement ; aucun matériel) construit par nmake, signé, chargé dans la VM, message lu dans WinDbg | Claude écrit, David charge | **Oui** (bcdedit de la VM, premier chargement) |
| 5g | Relecture de fond, CLAUDE.md, HISTORIQUE.md, tag `etape-5` | Claude | Non |

## Retour arrière

- **VM** : revenir à un instantané, ou supprimer la VM ; rien ne fuit vers Medabot.
- **Medabot** : désinstaller VMware, WinDbg et le WDK depuis les paramètres ; supprimer la règle de pare-feu de 5e ; en dernier recours, le point de restauration de 5b.
- **Scanner** : quand VMware le rend à Medabot, il retrouve WinUSB ; sinon débrancher et rebrancher. Retour au pilote Brother : [winusb.md](winusb.md).
