# capture_admin.ps1 : capture USBPcap lancée par la tâche planifiée « ds720d-capture ».
#
# Pourquoi ce script : USBPcapCMD doit ouvrir \\.\USBPcapN, ce qui exige les droits
# administrateur, et la session de Claude n'en a pas. Plutôt que de donner l'admin à
# toute la session (elle pourrait alors écrire sur F:), on n'élève que ce script-ci,
# qui ne sait faire qu'une chose : capturer un concentrateur vers ds720d-captures.
# Pourquoi pas une fenêtre UAC à chaque capture : David devrait être au PC pour la
# valider ; la tâche planifiée se déclenche avec « schtasks /run » sans élévation.
#
# Sécurité :
#   - la copie exécutée vit dans C:\ProgramData\ds720d\, modifiable seulement par un
#     administrateur (voir docs/captures.md) ; la modifier ici ne change rien tant que
#     David ne la recopie pas ;
#   - la demande vient d'un fichier écrit sans droits admin : chaque valeur est validée
#     (nom, concentrateur, durée) et rien d'autre n'est lu ;
#   - jamais d'écrasement d'une capture existante, durée bornée à 15 minutes.
#
# Protocole :
#   demande.txt  (écrit par Claude)  nom=1e-couleur-300-recto, hub=1, duree=300
#   stop         (créé par Claude)   arrête la capture
#   capture.log  (écrit ici)         début, fin, refus

$ErrorActionPreference = 'Stop'
$Dossier = 'C:\Users\morva\ds720d-captures'
$Demande = Join-Path $Dossier 'demande.txt'
$Stop = Join-Path $Dossier 'stop'
$Journal = Join-Path $Dossier 'capture.log'
$Usbpcap = 'C:\Program Files\USBPcap\USBPcapCMD.exe'

function Ecrire-Journal([string]$Message) {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Message" | Add-Content -Encoding utf8 -Path $Journal
}

function Refuser([string]$Raison) {
    Ecrire-Journal "refus : $Raison"
    exit 1
}

# --- Lecture et validation de la demande -------------------------------------
if (-not (Test-Path $Demande)) { Refuser 'pas de demande.txt' }
$p = @{}
foreach ($ligne in Get-Content -Path $Demande -TotalCount 10) {
    if ($ligne -match '^\s*(nom|hub|duree)\s*=\s*(\S+)\s*$') { $p[$Matches[1]] = $Matches[2] }
}

$nom = $p['nom']
if ($nom -notmatch '^[a-z0-9][a-z0-9-]{0,59}$') { Refuser "nom invalide « $nom »" }

$hub = if ($p.ContainsKey('hub')) { $p['hub'] } else { '1' }
if ($hub -notmatch '^[1-9]$') { Refuser "concentrateur invalide « $hub »" }

$duree = 300
if ($p.ContainsKey('duree')) {
    if ($p['duree'] -notmatch '^\d{1,3}$') { Refuser "durée invalide « $($p['duree']) »" }
    $duree = [int]$p['duree']
}
if ($duree -lt 5 -or $duree -gt 900) { Refuser "durée hors de [5, 900] s : $duree" }

$sortie = Join-Path $Dossier "$nom.pcap"
if (Test-Path $sortie) { Refuser "$nom.pcap existe déjà" }
if (Get-Process USBPcapCMD -ErrorAction SilentlyContinue) { Refuser 'une capture tourne déjà' }

# --- Capture --------------------------------------------------------------------
# -A : tous les appareils du concentrateur (le scanner change d'adresse au rebranchement).
# -s 262144 : assez pour un bloc d'image de 64 Kio plus l'en-tête USBPcap (la valeur
#   par défaut, 65 535, coupait 28 octets par bloc dans la capture 1c).
# -b 8388608 : tampon de 8 Mo dans le pilote, pour ne pas perdre de trames.
Remove-Item -Path $Stop -ErrorAction SilentlyContinue
$arguments = @('-d', "\\.\USBPcap$hub", '-A', '-s', '262144', '-b', '8388608', '-o', $sortie)
$proc = Start-Process -FilePath $Usbpcap -ArgumentList $arguments -WindowStyle Hidden -PassThru
Ecrire-Journal "début $nom (USBPcap$hub, $duree s au plus, pid $($proc.Id))"

$fin = (Get-Date).AddSeconds($duree)
while ((Get-Date) -lt $fin -and -not (Test-Path $Stop)) { Start-Sleep -Milliseconds 250 }

# USBPcapCMD se relance dans un second processus : on les arrête tous les deux.
Get-Process USBPcapCMD -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item -Path $Stop -ErrorAction SilentlyContinue
$taille = if (Test-Path $sortie) { (Get-Item $sortie).Length } else { 0 }
Ecrire-Journal "fin $nom ($taille o)"
