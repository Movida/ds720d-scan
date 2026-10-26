# Essai du Ctrl+C de ds720dk.exe pendant un scan, sans clavier (étape 6h).
#
# À lancer DANS LA VM, sans élévation (banc\vm\invite.ps1 ps), une feuille
# engagée dans le scanner :
#   powershell -ExecutionPolicy Bypass -File C:\Users\Public\ds720d\essai_ctrlc.ps1 NOM [SECONDES]
# NOM : préfixe des fichiers (NOM.brut, NOM.txt, NOM-sortie.txt, NOM-erreurs.txt).
# SECONDES : délai entre le premier bloc lu et l'interruption (1 par défaut).
#
# Pourquoi un script : depuis la console de VMware, la touche Ctrl n'arrive pas
# à la VM (essai du 25/10, des « c » simples) ; et, dans PowerShell, un Ctrl+C
# sur un programme dont la sortie est redirigée fait tuer ce programme par
# PowerShell, avant que son propre gestionnaire ne réagisse (même jour : trace
# coupée en pleine lecture, sans RELEASE UNIT). Ici, l'événement est produit
# par GenerateConsoleCtrlEvent (kernel32), exactement comme le clavier :
#   1. ds720dk.exe démarre dans la console de ce script (-NoNewWindow) ;
#   2. dès que la trace montre un bloc lu, ce script s'exclut lui-même du
#      Ctrl+C (SetConsoleCtrlHandler(NULL, TRUE)), après le démarrage de l'outil,
#      pour que l'outil n'hérite pas de cette exclusion ;
#   3. GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) envoie Ctrl+C à tous les
#      programmes de la console : seul ds720dk.exe y répond (sur_ctrl_c de
#      src/ds720d.c), en arrêtant la lecture au tour suivant et en envoyant
#      RELEASE UNIT.

param(
    [Parameter(Mandatory = $true, Position = 0)][ValidatePattern('^[A-Za-z0-9_-]+$')][string]$Nom,
    [Parameter(Position = 1)][ValidateRange(0, 30)][int]$Secondes = 1
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
# Noms neufs seulement, vérifiés avant d'écrire quoi que ce soit (depuis 6i :
# le compte rendu était ouvert avant ce contrôle, et écrasé en cas de refus).
foreach ($f in "$Nom.brut", "$Nom.txt", "$Nom-sortie.txt", "$Nom-erreurs.txt", "$Nom-rapport.txt") {
    if (Test-Path -LiteralPath $f) { throw "$f existe déjà : choisir un autre nom" }
}
# Le Ctrl+C touche toute la console, dont le PowerShell qui a lancé ce script
# (celui de invite.ps1 ps), qui s'arrête alors sans rendre sa sortie : le
# compte rendu est donc aussi écrit dans NOM-rapport.txt (constaté le 25/10).
Start-Transcript -LiteralPath "$PSScriptRoot\$Nom-rapport.txt" | Out-Null
Add-Type -Namespace Ds720d -Name Console -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GenerateConsoleCtrlEvent(uint evenement, uint groupe);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleCtrlHandler(System.IntPtr gestionnaire, bool ajouter);
'@

$p = Start-Process -FilePath .\ds720dk.exe -ArgumentList 'scan', '--sortie', "$PSScriptRoot\$Nom.brut", '--trace', "$Nom.txt" `
    -NoNewWindow -PassThru -RedirectStandardOutput "$Nom-sortie.txt" -RedirectStandardError "$Nom-erreurs.txt"

# Attente du premier bloc lu (« lecture 0xC3 »), 60 s au plus. On lit la
# sortie standard, où l'outil écrit aussi sa trace : le fichier de trace, lui,
# est ouvert par l'outil sans partage en lecture (premier essai du 25/10).
$debut = Get-Date
$bloc = $false
while (-not $p.HasExited -and ((Get-Date) - $debut).TotalSeconds -lt 60) {
    Start-Sleep -Milliseconds 200
    if (Select-String -LiteralPath "$Nom-sortie.txt" -Pattern 'lecture 0xC3' -Quiet -ErrorAction SilentlyContinue) { $bloc = $true; break }
}
if ($p.HasExited) { "l'outil s'est arrêté avant le premier bloc (code $($p.ExitCode))"; Get-Content "$Nom-erreurs.txt"; Stop-Transcript | Out-Null; exit 1 }
# Pas de bloc en 60 s (pas de feuille ?) : pas de Ctrl+C, qui n'éprouverait
# rien de ce qu'on cherche (depuis 6i : il partait quand même). L'outil finit
# seul, avec son propre délai d'attente de la feuille.
if (-not $bloc) {
    "aucun bloc lu en 60 s : pas de Ctrl+C envoyé, attente de la fin de l'outil"
    $p.WaitForExit()
    "outil terminé, code $($p.ExitCode)"
    Get-Content "$Nom-erreurs.txt"
    Stop-Transcript | Out-Null
    exit 1
}
Start-Sleep -Seconds $Secondes

[void][Ds720d.Console]::SetConsoleCtrlHandler([IntPtr]::Zero, $true)
$envoye = [Ds720d.Console]::GenerateConsoleCtrlEvent(0, 0)   # 0 : CTRL_C_EVENT ; 0 : toute la console
"Ctrl+C envoyé après $([int]((Get-Date) - $debut).TotalSeconds) s : $envoye"
$p.WaitForExit()
"outil terminé, code $($p.ExitCode)"
'--- erreurs de l''outil :'
Get-Content "$Nom-erreurs.txt"
'--- dernières commandes déposées :'
Select-String -LiteralPath "$Nom.txt" -Pattern 'DATA-OUT' | Select-Object -Last 3 | ForEach-Object { $_.Line.Substring(0, [Math]::Min(110, $_.Line.Length)) }
Stop-Transcript | Out-Null
