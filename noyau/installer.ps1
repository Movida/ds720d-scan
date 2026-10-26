# Installe ou retire le pilote du scanner dans la VM du banc noyau (étape 6b).
#
# DANS LA VM DS720D-NOYAU SEULEMENT, dans un PowerShell administrateur, par
# David (Claude n'a pas l'élévation dans la VM) :
#   cd C:\Users\Public\ds720d
#   powershell -ExecutionPolicy Bypass -File .\installer.ps1 <action>
#
# Actions :
#   etat                 ce qui est en place (sans droits admin)
#   certificat           accord A1 : certificat de test dans Root et TrustedPublisher
#   verificateur         accord A2 : Driver Verifier sur ds720d.sys (redémarrage ensuite)
#   verificateur-arret   retire Driver Verifier (redémarrage ensuite)
#   installer            accord A3 : paquet ajouté au magasin, scanner lié à ds720d
#   cycle [N]            désactive puis réactive le scanner N fois (1 par défaut)
#   activer              réactive le scanner seul (après une désactivation restée
#                        en attente, appliquée au redémarrage : étape 6h)
#   echo 0|1             copie des traces vers WinDbg coupée (0, par défaut) ou
#                        active (1) ; le pilote est rechargé pour la prendre en compte
#   retour               paquet retiré, scanner rendu à WinUSB (comme à l'étape 2)
#
# Garde-fou : le script refuse de tourner ailleurs que sur DS720D-NOYAU. Le
# 25/10, un bcdedit destiné à la VM a été tapé sur Medabot (CLAUDE.md) ; ici,
# c'est le script qui vérifie, avant toute chose.
#
# Fichiers attendus à côté du script (copiés par Claude, banc\vm\invite.ps1) :
#   paquet\ds720d.inf, paquet\ds720d.sys, paquet\ds720d.cat  (noyau\paquet.ps1)
#   ds720d-test.cer        partie publique du certificat de test
#   bascule_winusb.exe     pour l'action « retour »
#
# Les identifiants d'instance du scanner contiennent son numéro de série : le
# script ne les affiche jamais (CLAUDE.md), il désigne le scanner par son
# identifiant matériel et masque ceux que pnputil écrit (fonction Pnputil).
# bascule_winusb.exe (action « retour ») ne les affiche pas non plus.

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('etat', 'certificat', 'verificateur', 'verificateur-arret', 'installer', 'cycle', 'activer', 'echo', 'retour')]
    [string]$Action,
    # Nombre de cycles pour « cycle », 0 ou 1 pour « echo ».
    [Parameter(Position = 1)][string]$Valeur
)

$ErrorActionPreference = 'Stop'

# Le nom lu par l'API Windows (GetComputerName), pas la variable
# d'environnement COMPUTERNAME, qu'un « $env:COMPUTERNAME = … » dans la même
# console suffirait à changer (relecture 6i).
$machine = [Environment]::MachineName
if ($machine -ne 'DS720D-NOYAU') {
    throw "Ce script ne tourne que dans la VM DS720D-NOYAU ; ici : $machine. Rien n'a été fait."
}

$ID_SCANNER = 'USB\VID_04F9&PID_60E2'
# Empreinte du certificat de test (CLAUDE.md, noyau\signer.ps1) : on n'importe
# que lui, jamais un fichier .cer qui aurait été remplacé.
$EMPREINTE = 'B23EC996E38B082462453EFB9F495CCC2B93C2AF'
$paquetInf = Join-Path $PSScriptRoot 'paquet\ds720d.inf'
$cer = Join-Path $PSScriptRoot 'ds720d-test.cer'

function Exiger-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Action « $Action » : à lancer dans un PowerShell administrateur."
    }
}

# pnputil : 0 réussite, 3010 réussite avec redémarrage demandé
# (ERROR_SUCCESS_REBOOT_REQUIRED) ; tout autre code est un échec.
# pnputil affiche l'identifiant d'instance des appareils qu'il supprime,
# désactive ou réactive, numéro de série compris (constaté au premier essai,
# 25/10) : sa sortie passe par un filtre qui remplace la fin de tout
# identifiant d'instance USB ou USBSTOR (le numéro de série y est le
# troisième élément : USB\VID_…&PID_…\<série>, USBSTOR\Disk&Ven_…\<série>&0).
# Depuis 6i (relecture), la sortie d'erreur passe aussi par le filtre
# (2>&1) : un message d'échec peut citer l'appareil. Dans Windows
# PowerShell 5.1, chaque ligne d'erreur d'un programme redirigée ainsi devient
# une erreur PowerShell, qui arrêterait le script sous « Stop » : la
# préférence est donc « Continue » le temps de l'appel, dans cette fonction
# seulement ; l'échec se lit dans $LASTEXITCODE, qui reste celui de pnputil.
function Pnputil([string[]]$arguments) {
    Write-Host "> pnputil $($arguments -join ' ')"
    $ErrorActionPreference = 'Continue'
    & pnputil.exe @arguments 2>&1 | ForEach-Object {
        Write-Host ("$_" -replace '((?:USB|USBSTOR)\\[^\\\s]+\\)\S+', '$1(numéro de série masqué)')
    }
    if ($LASTEXITCODE -eq 3010) { Write-Host 'Windows demande un redémarrage pour finir.' }
    elseif ($LASTEXITCODE -ne 0) { throw "pnputil $($arguments[0]) a échoué ($LASTEXITCODE)" }
}

function Scanner {
    # Le scanner présent, désigné sans son identifiant d'instance.
    Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like "$ID_SCANNER\*" }
}

function Montrer-Scanner {
    $s = @(Scanner)
    if ($s.Count -eq 0) { Write-Host 'Scanner absent (pas connecté à la VM ?)'; return }
    $s | Get-PnpDeviceProperty DEVPKEY_Device_Service, DEVPKEY_Device_DriverInfPath, DEVPKEY_Device_DriverInfSection,
        DEVPKEY_Device_DriverVersion, DEVPKEY_Device_ProblemCode, DEVPKEY_Device_Class |
        Format-Table -AutoSize KeyName, Data | Out-String | Write-Host
    $s | Format-Table -AutoSize FriendlyName, Status | Out-String | Write-Host
}

# Nos paquets dans le magasin de pilotes : nom publié (oemNN.inf) et version.
# Il peut y en avoir deux le temps d'une mise à jour (action « installer »).
function Paquets-Publies {
    @(Get-WindowsDriver -Online | Where-Object { (Split-Path -Leaf $_.OriginalFileName) -eq 'ds720d.inf' })
}

switch ($Action) {
    'etat' {
        Write-Host "Machine : $machine"
        Montrer-Scanner
        foreach ($magasin in 'Root', 'TrustedPublisher') {
            $ok = Test-Path "Cert:\LocalMachine\$magasin\$EMPREINTE"
            Write-Host "Certificat de test dans LocalMachine\$magasin : $ok"
        }
        $svc = Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\ds720d -ErrorAction SilentlyContinue
        Write-Host "Service ds720d inscrit : $([bool]$svc)"
        if ($svc) {
            Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\ds720d\Parameters\Wdf -ErrorAction SilentlyContinue |
                Select-Object VerifierOn, VerboseOn | Format-List | Out-String | Write-Host
            $echo = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\ds720d\Parameters -ErrorAction SilentlyContinue).EchoDebogueur
            Write-Host "Copie des traces vers WinDbg (EchoDebogueur) : $(if ($echo) { $echo } else { '0 (absente)' })"
        }
        # Pilotes soumis à Driver Verifier, lus dans le registre qu'écrit
        # verifier.exe (lisible sans droits admin, contrairement à /querysettings).
        $v = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -ErrorAction SilentlyContinue
        Write-Host "Driver Verifier : pilotes « $($v.VerifyDrivers) », options 0x$('{0:X}' -f [int]$v.VerifyDriverLevel)"
    }
    'certificat' {
        # Accord A1 (25/10/2026) : le certificat de test devient une racine de
        # confiance (Root) et un éditeur approuvé (TrustedPublisher), DANS LA VM.
        # Root : la chaîne de signature du catalogue aboutit à une racine
        # approuvée. TrustedPublisher : pnputil installe sans demander de
        # confirmation pour cet éditeur (doc WDK, « Installing a Test-Signed
        # Driver Package on the Test Computer »).
        #
        # Par la classe X509Store de .NET plutôt que par Import-Certificate :
        # premier essai du 25/10, Root importé mais TrustedPublisher refusé
        # (E_ACCESSDENIED, en administrateur), alors que ce magasin n'existait
        # pas encore dans le registre de la VM. Cause probable : le fournisseur
        # Cert: de PowerShell 5.1 n'ouvre qu'un magasin existant. X509Store,
        # ouvert en lecture-écriture sans OpenExistingOnly, crée le magasin
        # s'il manque ; ajouter un certificat déjà présent ne change rien.
        Exiger-Admin
        $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cer)
        if ($c.Thumbprint -ne $EMPREINTE) { throw "certificat inattendu : $($c.Thumbprint) au lieu de $EMPREINTE" }
        foreach ($magasin in 'Root', 'TrustedPublisher') {
            $m = New-Object Security.Cryptography.X509Certificates.X509Store($magasin, 'LocalMachine')
            $m.Open('ReadWrite')
            try { $m.Add($c) } finally { $m.Close() }
            if (-not (Test-Path "Cert:\LocalMachine\$magasin\$EMPREINTE")) { throw "absent de LocalMachine\$magasin après l'ajout" }
            Write-Host "présent dans LocalMachine\$magasin : $($c.Subject) ($EMPREINTE)"
        }
    }
    'verificateur' {
        # Accord A2 (25/10/2026). /standard : contrôles standard de Driver
        # Verifier (pool spécial, IRQL, E/S, interblocages…) ; /driver : sur
        # ds720d.sys seul. Effet au prochain démarrage de la VM. Le vérificateur
        # KMDF, lui, est posé par l'INF (VerifierOn).
        Exiger-Admin
        & verifier.exe /standard /driver ds720d.sys
        Write-Host "verifier : code $LASTEXITCODE. Redémarrer la VM pour que ce soit actif."
    }
    'verificateur-arret' {
        Exiger-Admin
        & verifier.exe /reset
        Write-Host "verifier : code $LASTEXITCODE. Redémarrer la VM pour que ce soit effectif."
    }
    'installer' {
        # Accord A3 (25/10/2026) : premier chargement de ds720d.sys.
        # 1. Le paquet entre dans le magasin de pilotes, sans encore toucher au
        #    scanner (pas de /install : on garde la main sur le moment de la bascule).
        # 2. Le nœud du scanner est supprimé puis redétecté : Windows choisit
        #    alors, parmi les pilotes du magasin, le mieux classé pour lui. Le
        #    nôtre répond à son identifiant matériel exact ; USBSTOR seulement à
        #    son identifiant compatible, moins bien classé (doc WDK, « How
        #    Windows Ranks Drivers ») ; le modèle générique de WinUSB à aucun.
        #    Pourquoi pas « pnputil /add-driver … /install » seul : il ne
        #    remplace le pilote en place que s'il juge le nouveau meilleur, et
        #    WinUSB a été posé à la main (bascule_winusb.exe) ; supprimer et
        #    redétecter donne toujours le même chemin, le même que le retour de
        #    l'étape 2 (docs/winusb.md).
        # Montage automatique coupé dans la VM depuis 5d : si USBSTOR prenait
        # malgré tout le scanner, aucun volume ne serait monté.
        #
        # Mise à jour (depuis 6c) : la même suite installe une nouvelle version
        # par-dessus l'ancienne. À la redétection, Windows préfère le paquet à
        # la version la plus haute (DriverVer de l'INF, à monter à chaque
        # version) ; l'ancien, devenu inutile, est ensuite retiré du magasin.
        #
        # Depuis 6i (relecture) : on attend que le scanner tourne bien sur le
        # nouveau paquet avant de retirer quoi que ce soit. Jusqu'en 6h, le
        # script relevait le paquet en service après 3 s fixes ; si Windows
        # n'avait pas fini la redétection, il pouvait lire l'ancien et retirer
        # le nouveau. Le nouveau se reconnaît à sa version, lue dans l'INF.
        Exiger-Admin
        if (-not (Scanner)) { throw 'scanner absent : le connecter à la VM (menu de VMware) avant' }
        $version = if ((Get-Content -LiteralPath $paquetInf -Raw) -match '(?m)^DriverVer\s*=\s*[^,]+,\s*([0-9.]+)') { $Matches[1] }
        if (-not $version) { throw "DriverVer introuvable dans $paquetInf" }
        Pnputil @('/add-driver', $paquetInf)
        $nouveau = @(Paquets-Publies | Where-Object { $_.Version -eq $version })
        if ($nouveau.Count -ne 1) { throw "paquet $version : $($nouveau.Count) exemplaire(s) dans le magasin au lieu d'un ; rien d'autre n'est fait" }
        $nouveau = $nouveau[0].Driver
        Write-Host "nouveau paquet : $nouveau (version $version)"
        Pnputil @('/remove-device', '/deviceid', $ID_SCANNER)
        Pnputil @('/scan-devices')
        # Jusqu'à 30 s, relevé chaque seconde : la redétection est asynchrone.
        $enService = $null
        for ($i = 0; $i -lt 30 -and $enService -ne $nouveau; $i++) {
            Start-Sleep -Seconds 1
            $s = Scanner
            $enService = if ($s) { ($s | Get-PnpDeviceProperty DEVPKEY_Device_DriverInfPath).Data }
        }
        if ($enService -ne $nouveau) {
            Montrer-Scanner
            throw "le scanner n'a pas pris $nouveau (en service : « $enService ») ; aucun paquet n'a été retiré du magasin"
        }
        foreach ($p in Paquets-Publies) {
            if ($p.Driver -ne $nouveau) {
                Write-Host "ancien paquet $($p.Driver) (version $($p.Version)) retiré du magasin"
                Pnputil @('/delete-driver', $p.Driver)
            }
        }
        Montrer-Scanner
    }
    'cycle' {
        # Désactiver arrête l'appareil (D0Exit, ReleaseHardware) sans le
        # supprimer ; réactiver le redémarre (PrepareHardware, D0Entry). Sous
        # Driver Verifier, une fuite ou une faute s'y voit vite.
        Exiger-Admin
        $fois = if ($Valeur) { [int]$Valeur } else { 1 }
        if ($fois -lt 1 -or $fois -gt 100) { throw 'cycle N : N de 1 à 100' }
        for ($i = 1; $i -le $fois; $i++) {
            Write-Host "--- cycle $i / $fois"
            Pnputil @('/disable-device', '/deviceid', $ID_SCANNER)
            Pnputil @('/enable-device', '/deviceid', $ID_SCANNER)
        }
        Montrer-Scanner
    }
    'activer' {
        # Désactiver un scanner ouvert par l'outil est refusé par Windows, qui
        # garde la désactivation en attente et l'applique au redémarrage
        # (étape 6h) : le scanner revient alors désactivé. Cette action le
        # réactive, sans passer par une désactivation.
        Exiger-Admin
        Pnputil @('/enable-device', '/deviceid', $ID_SCANNER)
        Montrer-Scanner
    }
    'echo' {
        # Valeur EchoDebogueur de la clé Parameters du service, lue par
        # DriverEntry (noyau/wpp.h) : 1 recopie chaque trace vers WinDbg, 0 la
        # laisse dans l'enregistreur en mémoire seulement. Coupée par défaut :
        # avec KDNET, des rafales de messages ont précédé deux plantages
        # (docs/pilote.md, 6d). Désactiver puis réactiver le scanner décharge
        # et recharge le pilote, qui relit alors la valeur.
        Exiger-Admin
        if ($Valeur -ne '0' -and $Valeur -ne '1') { throw 'echo 0 ou echo 1' }
        New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ds720d\Parameters -Name EchoDebogueur `
            -PropertyType DWord -Value ([int]$Valeur) -Force | Out-Null
        Write-Host "EchoDebogueur = $Valeur"
        Pnputil @('/disable-device', '/deviceid', $ID_SCANNER)
        Pnputil @('/enable-device', '/deviceid', $ID_SCANNER)
        Montrer-Scanner
    }
    'retour' {
        # Retour à WinUSB : le paquet est désinstallé du scanner et retiré du
        # magasin ; le scanner retombe sur USBSTOR (montage coupé, aucun volume),
        # puis bascule_winusb.exe le passe sous WinUSB, comme à l'étape 2.
        Exiger-Admin
        $paquets = Paquets-Publies
        if ($paquets.Count -eq 0) { Write-Host 'paquet ds720d absent du magasin' }
        foreach ($p in $paquets) { Pnputil @('/delete-driver', $p.Driver, '/uninstall') }
        Start-Sleep -Seconds 3
        & (Join-Path $PSScriptRoot 'bascule_winusb.exe') --oui
        if ($LASTEXITCODE -ne 0) { throw "bascule_winusb a échoué ($LASTEXITCODE)" }
        Montrer-Scanner
    }
}
