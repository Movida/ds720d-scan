# Fait le paquet d'installation du pilote du scanner (étape 6b).
#
# Usage, après « construire.cmd noyau » :  .\noyau\paquet.ps1
#
# Un paquet de pilote PnP, c'est trois fichiers dans un même dossier :
#   ds720d.inf  ce qu'il faut installer, et pour quel appareil ;
#   ds720d.sys  le pilote, signé ;
#   ds720d.cat  le catalogue : l'empreinte de chaque fichier du paquet, signé.
# Windows n'installe un paquet que si son catalogue est signé par un éditeur
# qu'il approuve ; c'est le catalogue, pas le .sys, que vérifie pnputil. Le
# .sys est signé lui aussi : c'est sa propre signature que le noyau vérifie au
# chargement (doc WDK, « Signing a Driver During Development and Testing »).
#
# Étapes, dans cet ordre :
#   1. copie de l'INF et du .sys dans out\noyau\paquet, vidé d'abord ;
#   2. signature du .sys (noyau\signer.ps1, certificat de test) ;
#   3. InfVerif /w : l'INF contrôlée selon les règles des pilotes Windows ;
#   4. Inf2Cat : le catalogue, après contrôle que l'INF couvre la version de
#      Windows visée ;
#   5. signature du catalogue.
# Le .sys est signé avant Inf2Cat par habitude, mais l'ordre est sans effet :
# l'empreinte Authenticode d'un fichier PE, celle que retient le catalogue,
# exclut sa propre signature.
#
# Pourquoi un script et pas le Makefile : la signature a besoin du certificat
# du magasin de l'utilisateur (signer.ps1), et Inf2Cat d'un dossier qui ne
# contienne que le paquet.

$ErrorActionPreference = 'Stop'
$depot = Split-Path -Parent $PSScriptRoot
$wdk = 'C:\Program Files (x86)\Windows Kits\10'
$infverif = "$wdk\Tools\10.0.26100.0\x64\infverif.exe"
# Inf2Cat n'existe qu'en version x86 dans le WDK ; il tourne très bien sur x64.
$inf2cat = "$wdk\bin\10.0.26100.0\x86\Inf2Cat.exe"
$paquet = Join-Path $depot 'out\noyau\paquet'
$sys = Join-Path $depot 'out\noyau\ds720d.sys'

if (-not (Test-Path -LiteralPath $sys)) { throw "$sys absent : lancer d'abord construire.cmd noyau" }

# 1. Dossier du paquet, recréé vide : Inf2Cat cataloguerait tout fichier resté là.
if (Test-Path -LiteralPath $paquet) { Remove-Item -LiteralPath $paquet -Recurse -Force }
New-Item -ItemType Directory -Path $paquet | Out-Null
Copy-Item -LiteralPath (Join-Path $depot 'noyau\ds720d.inf'), $sys -Destination $paquet

# signer.ps1 exporte la partie publique du certificat à côté du fichier signé :
# on la range dans out\noyau, hors du paquet, pour qu'Inf2Cat ne la prenne pas
# pour un fichier du pilote. C'est elle que la VM importe (accord A1).
function Signer([string]$fichier) {
    & (Join-Path $PSScriptRoot 'signer.ps1') $fichier
    Move-Item -Force -LiteralPath (Join-Path $paquet 'ds720d-test.cer') -Destination (Join-Path $depot 'out\noyau')
}

# 2. Signature du pilote.
Signer (Join-Path $paquet 'ds720d.sys')

# 3. InfVerif /w : règles des « pilotes Windows » (doc WDK, InfVerif), les plus
# exigeantes après celles de la certification WHQL (/h), qui ne nous concerne
# pas. /v détaille chaque contrôle.
& $infverif /v /w (Join-Path $paquet 'ds720d.inf')
if ($LASTEXITCODE -ne 0) { throw "InfVerif a refusé l'INF ($LASTEXITCODE)" }

# 4. Catalogue. /os:10_GE_X64 : Windows 11 24H2 et suivants en x64, la branche
# du Windows de la VM (noyau 26100, docs/noyau.md). Inf2Cat vérifie que l'INF
# a une section de modèles qui s'applique à cette version (ici
# NTamd64.10.0...16299) avant d'écrire le catalogue. Ses messages sont en
# anglais, son code de sortie fait foi.
& $inf2cat /driver:$paquet /os:10_GE_X64 /verbose
if ($LASTEXITCODE -ne 0) { throw "Inf2Cat a échoué ($LASTEXITCODE)" }

# 5. Signature du catalogue.
Signer (Join-Path $paquet 'ds720d.cat')

# Récapitulatif : contenu et empreintes, pour vérifier après copie dans la VM
# que ce sont bien ces fichiers-là qui s'installent.
Get-ChildItem -LiteralPath $paquet | ForEach-Object {
    '{0,-16} {1,8} o  SHA-256 {2}' -f $_.Name, $_.Length, (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
}
