# Signe un pilote du projet avec le certificat de test (étape 5f).
#
# Usage : .\noyau\signer.ps1 out\noyau\bonjour.sys
#
# Le certificat « CN=ds720d test (VM uniquement) » est auto-signé et rangé dans
# le magasin personnel de l'utilisateur de Medabot (Cert:\CurrentUser\My) :
# créé au premier passage (accord écrit de David du 25/10), sans droits admin,
# il ne touche à aucune règle de confiance de Windows. Sa clé privée n'est pas
# exportable et ne quitte jamais ce magasin ; seule la partie publique est
# écrite dans out\noyau\ds720d-test.cer, pour la VM si elle doit l'importer.
# Pour bonjour.sys (service lancé par sc), la VM n'en a pas eu besoin ; une
# installation par INF et pnputil (étape 6) demandera de l'importer dans les
# magasins Root et TrustedPublisher de la VM.
#
# JAMAIS sur Medabot : importer ce .cer dans ses magasins de confiance ferait
# accepter par Medabot tout ce que signe cette clé, que n'importe quel
# programme lancé sous la session de David peut utiliser.
#
# Pourquoi une signature de test : avec `bcdedit /set testsigning on` (dans la
# VM seulement), le noyau accepte un pilote signé par n'importe quel
# certificat ; sans signature du tout, il le refuse quand même (doc WDK,
# « Test Signing »). Medabot refuse ce pilote : son Secure Boot interdit
# testsigning (constaté en 5f). C'est voulu, il ne se charge que dans la VM.
#
# Pourquoi New-SelfSignedCertificate et pas MakeCert.exe du WDK : MakeCert est
# déclaré obsolète par Microsoft et produit par défaut une clé SHA-1 ;
# PowerShell crée directement un certificat de signature de code SHA-256.

param([Parameter(Mandatory = $true)][string]$Pilote)

$ErrorActionPreference = 'Stop'
$sujet = 'CN=ds720d test (VM uniquement)'
$signtool = 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe'

if (-not (Test-Path -LiteralPath $Pilote -PathType Leaf)) { throw "pilote introuvable : $Pilote" }
# Chemin absolu : un nom sans dossier ferait échouer Join-Path plus bas.
$Pilote = (Resolve-Path -LiteralPath $Pilote).Path

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Subject -eq $sujet | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $sujet `
        -CertStoreLocation Cert:\CurrentUser\My -KeyExportPolicy NonExportable `
        -HashAlgorithm SHA256 -KeyLength 3072 -NotAfter (Get-Date).AddYears(2)
    Write-Host "certificat de test créé : $($cert.Thumbprint)"
}
$cer = Join-Path (Split-Path -Parent $Pilote) 'ds720d-test.cer'
Export-Certificate -Cert $cert -FilePath $cer -Type CERT | Out-Null

# /fd sha256 : empreinte du fichier en SHA-256 ; /sha1 : choix du certificat par
# son empreinte (pas d'ambiguïté si un autre certificat portait le même nom).
# Pas d'horodatage (/tr) : il demanderait un serveur en ligne, inutile pour une
# signature de test dont le certificat n'est de toute façon pas reconnu.
& $signtool sign /fd sha256 /sha1 $cert.Thumbprint /s My $Pilote
if ($LASTEXITCODE -ne 0) { throw "signtool a échoué ($LASTEXITCODE)" }

$sig = Get-AuthenticodeSignature -LiteralPath $Pilote
# Statut attendu : UnknownError (racine non approuvée), puisque le certificat
# n'est approuvé nulle part ; ce qui compte est que la signature soit bien la
# nôtre, d'où la comparaison des empreintes.
if ($sig.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
    throw "signature inattendue : $($sig.SignerCertificate.Thumbprint) au lieu de $($cert.Thumbprint)"
}
Write-Host "signé par : $($sig.SignerCertificate.Subject) ($($sig.SignerCertificate.Thumbprint)), statut $($sig.Status)"
