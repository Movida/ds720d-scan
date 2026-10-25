# Commandes dans la VM du banc noyau, par vmrun et les VMware Tools.
#
# Usage :
#   .\banc\vm\invite.ps1 lancer   <programme> [arguments]    # attend la fin
#   .\banc\vm\invite.ps1 vers     <fichier hôte> <fichier invité>
#   .\banc\vm\invite.ps1 depuis   <fichier invité> <fichier hôte>
#   .\banc\vm\invite.ps1 dossier  <dossier invité>          # le crée s'il manque
#   .\banc\vm\invite.ps1 ps       "<commandes PowerShell>"  # sortie affichée
#   .\banc\vm\invite.ps1 etat                               # état de la VM en lecture seule
#
# Avec « lancer », mettre `--` avant le programme si un argument commence par
# un tiret (`lancer -- prog -a`) : sans lui, PowerShell prendrait `-a` pour
# une abréviation de -Action.
#
# Le mot de passe du compte « david » de la VM n'est écrit nulle part : David
# l'a rangé dans le gestionnaire d'identifiants Windows de Medabot
# (`cmdkey /generic:ds720d-vm /user:david /pass`), ce script le lit par
# CredRead (advapi32, identifiant générique) et ne l'affiche jamais.
# Pourquoi un mot de passe : vmrun refuse les opérations invitées sur un
# compte qui n'en a pas (« ne prend pas en charge les mots de passe vides »).
# Limite connue : vmrun le reçoit en argument, donc visible dans la liste
# des processus de Medabot le temps de l'appel, et dans les journaux qui
# enregistrent les lignes de commande (audit 4688, Sysmon) s'ils sont
# activés ; acceptable pour un mot de passe propre à cette VM jetable, qui
# ne doit servir nulle part ailleurs. Un mot de passe contenant un guillemet
# casserait la transmission des arguments à vmrun : l'éviter.
#
# Chemin de la VM fixe : celui que crée creer_vm.ps1 par défaut.

param(
    [Parameter(Mandatory = $true, Position = 0)][ValidateSet('lancer', 'vers', 'depuis', 'dossier', 'ps', 'etat')][string]$Action,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Reste
)

$ErrorActionPreference = 'Stop'
$vmrun = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe'
$vmx = 'D:\VM\ds720d-noyau\ds720d-noyau.vmx'

Add-Type -Namespace Ds720d -Name Cred -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
public struct CREDENTIAL {
    public int Flags; public int Type; public string TargetName; public string Comment;
    public long LastWritten; public int CredentialBlobSize; public System.IntPtr CredentialBlob;
    public int Persist; public int AttributeCount; public System.IntPtr Attributes;
    public string TargetAlias; public string UserName;
}
[System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern bool CredRead(string target, int type, int flags, out System.IntPtr cred);
[System.Runtime.InteropServices.DllImport("advapi32.dll")]
public static extern void CredFree(System.IntPtr cred);
'@

function Lire-Identifiant {
    $p = [IntPtr]::Zero
    # Type 1 : CRED_TYPE_GENERIC, celui que crée `cmdkey /generic`.
    if (-not [Ds720d.Cred]::CredRead('ds720d-vm', 1, 0, [ref]$p)) {
        throw "Identifiant « ds720d-vm » absent : cmdkey /generic:ds720d-vm /user:david /pass"
    }
    try {
        $c = [Runtime.InteropServices.Marshal]::PtrToStructure($p, [type][Ds720d.Cred+CREDENTIAL])
        # Taille en octets, caractères UTF-16 de deux octets : division entière.
        $mdp = [Runtime.InteropServices.Marshal]::PtrToStringUni($c.CredentialBlob, $c.CredentialBlobSize -shr 1)
        return @{ Utilisateur = $c.UserName; MotDePasse = $mdp }
    } finally { [Ds720d.Cred]::CredFree($p) }
}

function Vmrun-Invite([string[]]$arguments) {
    $id = Lire-Identifiant
    & $vmrun -T ws -gu $id.Utilisateur -gp $id.MotDePasse @arguments
    if ($LASTEXITCODE -ne 0) { throw "vmrun $($arguments[0]) a échoué ($LASTEXITCODE)" }
}

function PowerShell-Invite([string]$commandes) {
    # Le script passe par un fichier : vmrun recolle les arguments en une
    # seule ligne de commande, et les guillemets, accolades et redirections
    # d'un -Command ou d'un cmd /c ne survivent pas à ce recollage.
    # Il tourne avec le jeton filtré de « david » (pas d'élévation : ce qui
    # demande les droits admin dans la VM, c'est David qui le lance).
    $scriptHote = Join-Path $env:TEMP 'ds720d-invite.ps1'
    $scriptInvite = 'C:\Users\Public\ds720d-invite.ps1'
    $sortieInvite = 'C:\Users\Public\ds720d-invite.txt'
    # Palliatif signalé : le script sort toujours par « exit 0 », car le code
    # de sortie de la dernière commande (bcdedit sans élévation par exemple)
    # ne dit rien de ce qui a été relevé. Pour qu'un échec ne passe pas pour
    # un succès, le nombre d'erreurs PowerShell est écrit en dernière ligne de
    # la sortie (*> écrit en UTF-16, d'où -Encoding Unicode à l'ajout).
    $corps = "`$Error.Clear(); & { $commandes } *> $sortieInvite; " +
             "`"# erreurs PowerShell dans la VM : `$(`$Error.Count)`" | Out-File -Append -Encoding Unicode $sortieInvite; exit 0"
    [IO.File]::WriteAllText($scriptHote, $corps, (New-Object Text.UTF8Encoding($true)))
    Vmrun-Invite @('copyFileFromHostToGuest', $vmx, $scriptHote, $scriptInvite)
    Vmrun-Invite @('runProgramInGuest', $vmx, 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                   '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $scriptInvite)
    $local = Join-Path $env:TEMP 'ds720d-invite.txt'
    Vmrun-Invite @('copyFileFromGuestToHost', $vmx, $sortieInvite, $local)
    Get-Content -LiteralPath $local -Encoding Unicode
}

switch ($Action) {
    'lancer' {
        if ($Reste.Count -lt 1) { throw 'lancer <programme> [arguments]' }
        Vmrun-Invite (@('runProgramInGuest', $vmx, '-activeWindow', $Reste[0]) + ($Reste | Select-Object -Skip 1))
    }
    'vers' {
        if ($Reste.Count -ne 2) { throw 'vers <fichier hôte> <fichier invité>' }
        Vmrun-Invite @('copyFileFromHostToGuest', $vmx, $Reste[0], $Reste[1])
    }
    'depuis' {
        if ($Reste.Count -ne 2) { throw 'depuis <fichier invité> <fichier hôte>' }
        Vmrun-Invite @('copyFileFromGuestToHost', $vmx, $Reste[0], $Reste[1])
    }
    'dossier' {
        if ($Reste.Count -ne 1) { throw 'dossier <dossier invité>' }
        $id = Lire-Identifiant
        $existe = & $vmrun -T ws -gu $id.Utilisateur -gp $id.MotDePasse directoryExistsInGuest $vmx $Reste[0]
        if ($existe -notmatch 'exists') { Vmrun-Invite @('createDirectoryInGuest', $vmx, $Reste[0]) }
    }
    'ps' {
        # Un bloc PowerShell exécuté dans la VM, sortie rapatriée et affichée.
        if ($Reste.Count -ne 1) { throw 'ps "<commandes PowerShell>"' }
        PowerShell-Invite $Reste[0]
    }
    'etat' {
        # Lecture seule : version, édition, Secure Boot, VBS/HVCI, réseau,
        # contrôleurs USB, entrée de démarrage, volumes. Rien n'est modifié.
        PowerShell-Invite ('Get-ComputerInfo -Property OsName,OsVersion,OsBuildNumber,WindowsEditionId | Format-List; ' +
            'try { "SecureBoot=" + (Confirm-SecureBootUEFI) } catch { "SecureBoot=" + $_.Exception.Message }; ' +
            '$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard; ' +
            '"VBS=" + $dg.VirtualizationBasedSecurityStatus + " services=" + ($dg.SecurityServicesRunning -join ","); ' +
            '"HVCI(registre)=" + (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity -ErrorAction SilentlyContinue).Enabled; ' +
            '"NoAutoMount=" + (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\mountmgr -ErrorAction SilentlyContinue).NoAutoMount; ' +
            'Get-NetAdapter | Format-Table -AutoSize Name,InterfaceDescription,Status,MacAddress; ' +
            'Get-NetIPAddress -AddressFamily IPv4 | Format-Table -AutoSize InterfaceAlias,IPAddress,PrefixLength; ' +
            'Get-PnpDevice -PresentOnly | Where-Object { $_.Class -eq ''USB'' } | Format-Table -AutoSize FriendlyName,Status; ' +
            'bcdedit /enum ''{current}''; mountvol')
    }
}
