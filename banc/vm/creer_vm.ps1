# Crée la VM du banc noyau (docs/noyau.md, sous-étape 5c), sans la démarrer.
#
# Usage : .\banc\vm\creer_vm.ps1 -Iso D:\Downloads\<iso Windows 11>.iso
#
# Trois choses, toutes vérifiables avant le premier démarrage :
#   1. le disque NVMe, créé par vmware-vdiskmanager (outil de VMware) ;
#   2. autounattend.iso, écrite à la main par iso_unattend.py ;
#   3. le fichier .vmx, écrit ici réglage par réglage.
# Pourquoi écrire le .vmx à la main plutôt que passer par l'assistant de
# VMware : chaque réglage est choisi et justifié ici, et la VM se recrée à
# l'identique. Les commentaires restent dans ce script : VMware réécrit le
# .vmx à chaque modification et n'y garde pas les lignes de commentaire.
#
# Le script ne démarre rien, ne touche ni à Medabot ni au scanner ; il refuse
# d'écraser une VM existante.

param(
    [Parameter(Mandatory = $true)][string]$Iso,
    [string]$Dossier = 'D:\VM\ds720d-noyau'
)

$ErrorActionPreference = 'Stop'
$nom = 'ds720d-noyau'
$vmware = 'C:\Program Files\VMware\VMware Workstation'
$ici = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path -LiteralPath $Iso -PathType Leaf)) { throw "ISO introuvable : $Iso" }
$Iso = (Resolve-Path -LiteralPath $Iso).Path
$vmx = Join-Path $Dossier "$nom.vmx"
if (Test-Path -LiteralPath $Dossier) { throw "$Dossier existe déjà : rien n'est écrasé (supprimer la VM d'abord)" }
New-Item -ItemType Directory -Path $Dossier | Out-Null

# 1. Disque de 80 Go, un seul fichier qui grandit à l'usage (type 0) : la
#    place sur D: n'est prise qu'au fur et à mesure. « lsilogic » est le type
#    d'adaptateur à donner pour un disque qui ira sur NVMe (aide de l'outil :
#    « Pass lsilogic for other adapter types »).
& "$vmware\vmware-vdiskmanager.exe" -c -s 80GB -a lsilogic -t 0 (Join-Path $Dossier "$nom.vmdk")
if ($LASTEXITCODE -ne 0) { throw "vmware-vdiskmanager a échoué ($LASTEXITCODE)" }

# 2. Fichier de réponse sur une ISO 9660 + Joliet faite main.
$isoReponse = Join-Path $Dossier 'autounattend.iso'
& py -I (Join-Path $ici 'iso_unattend.py') (Join-Path $ici 'autounattend.xml') $isoReponse
if ($LASTEXITCODE -ne 0) { throw "iso_unattend.py a échoué ($LASTEXITCODE)" }

# 3. Le .vmx.
$lignes = @(
    '.encoding = "UTF-8"'
    'config.version = "8"'
    # Matériel virtuel 21 : pris en charge depuis Workstation 17.5, assez
    # récent pour NVMe, xHCI et e1000e ; pas besoin du dernier cri.
    'virtualHW.version = "21"'
    "displayName = `"$nom`""
    # Déclaré Windows 11 64 bits : VMware règle ses défauts invisibles
    # (horloge, APIC) pour ce système.
    'guestOS = "windows11-64"'
    # Réponse automatique (par défaut) aux messages de VMware : au premier
    # démarrage, l'avis sur les atténuations du canal latéral (on les garde)
    # bloquait la mise sous tension tant que personne ne cliquait OK.
    'msg.autoAnswer = "TRUE"'

    # Firmware UEFI, comme un PC actuel, et Secure Boot coupé dès la
    # création : sinon le noyau refuse le test-signing (accord de David du
    # 25/10, docs/noyau.md). N'affecte que la VM, Medabot garde le sien.
    'firmware = "efi"'
    'uefi.secureBoot.enabled = "FALSE"'

    # 4 processeurs virtuels sur un seul socket, 8 Go : moitié moins que le
    # Ryzen et un quart de la RAM, Medabot reste à l'aise.
    'numvcpus = "4"'
    'cpuid.coresPerSocket = "4"'
    'memsize = "8192"'

    # Ponts PCIe : NVMe et e1000e sont des cartes PCI Express, il leur faut
    # des ports racine (pciBridge4 à 7, disposition standard de VMware).
    'pciBridge0.present = "TRUE"'
    'pciBridge4.present = "TRUE"', 'pciBridge4.virtualDev = "pcieRootPort"', 'pciBridge4.functions = "8"'
    'pciBridge5.present = "TRUE"', 'pciBridge5.virtualDev = "pcieRootPort"', 'pciBridge5.functions = "8"'
    'pciBridge6.present = "TRUE"', 'pciBridge6.virtualDev = "pcieRootPort"', 'pciBridge6.functions = "8"'
    'pciBridge7.present = "TRUE"', 'pciBridge7.virtualDev = "pcieRootPort"', 'pciBridge7.functions = "8"'

    # Disque système en NVMe : pilote natif de Windows 11 (stornvme), rien à
    # ajouter pendant l'installation.
    'nvme0.present = "TRUE"'
    'nvme0:0.present = "TRUE"'
    "nvme0:0.fileName = `"$nom.vmdk`""

    # Deux lecteurs de CD sur SATA (pilote natif aussi) : l'ISO de Windows et
    # le fichier de réponse. À retirer après l'installation.
    'sata0.present = "TRUE"'
    'sata0:0.present = "TRUE"'
    'sata0:0.deviceType = "cdrom-image"'
    "sata0:0.fileName = `"$Iso`""
    'sata0:1.present = "TRUE"'
    'sata0:1.deviceType = "cdrom-image"'
    'sata0:1.fileName = "autounattend.iso"'
    # Démarrage sur le NVMe d'abord : vierge au premier démarrage, le
    # firmware passe au CD. Ensuite, Windows démarre seul. L'ordre inverse
    # (essayé le 25/10) repasse par « Press any key to boot from CD » à
    # chaque redémarrage : une touche de trop relance l'installation.
    'bios.bootOrder = "hdd,cdrom"'

    # Réseau en NAT (VMnet8, Medabot y est 192.168.150.1) : Internet pour
    # l'installation et, à l'étape 5e, le transport de KDNET. Carte e1000e
    # (Intel 82574L émulée) : dans la liste des cartes prises en charge par
    # KDNET ; vmxnet3 n'y est pas et demanderait les VMware Tools.
    'ethernet0.present = "TRUE"'
    'ethernet0.connectionType = "nat"'
    'ethernet0.virtualDev = "e1000e"'
    'ethernet0.addressType = "generated"'

    # USB : contrôleurs EHCI (USB 2.0, celui que verra le scanner, appareil
    # haute vitesse) et xHCI. Rien n'est connecté d'office : le scanner ne
    # passe à la VM qu'à la sous-étape 5d, montage automatique coupé avant.
    'usb.present = "TRUE"'
    'ehci.present = "TRUE"'
    'usb_xhci.present = "TRUE"'
    'usb.generic.autoconnect = "FALSE"'

    # Affichage et pièces sans intérêt pour le banc : pas de son, pas de
    # disquette, pas d'imprimante virtuelle.
    'svga.present = "TRUE"'
    'sound.present = "FALSE"'
    'floppy0.present = "FALSE"'
    'serial0.present = "FALSE"'
    'printers.enabled = "FALSE"'
    'vmci0.present = "TRUE"'
    'hpet0.present = "TRUE"'
    # L'heure de la VM n'est pas recalée sur Medabot par VMware : en
    # débogage noyau, la VM reste figée sur un point d'arrêt, un recalage
    # brutal fausserait les horodatages des traces.
    'tools.syncTime = "FALSE"'
)
# UTF-8 sans BOM, comme les .vmx de VMware.
[System.IO.File]::WriteAllLines($vmx, [string[]]$lignes, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "VM écrite : $vmx"
Get-ChildItem -LiteralPath $Dossier | ForEach-Object { Write-Host ("  {0,-24} {1,12:N0} o" -f $_.Name, $_.Length) }
