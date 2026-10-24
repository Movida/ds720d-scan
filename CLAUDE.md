# Règles du projet ds720d-scan

- Répondre en français. David apprend : expliquer le pourquoi de chaque étape.
- Viser la solution la plus juste et propre ; signaler tout palliatif comme tel.
- **Ne jamais formater ni écrire dans le faux disque du scanner** (volume FAT12 de 1 Mo, lettre F: sur Medabot, `\\.\PhysicalDrive3`) : c'est son canal de commande. Lecture et commandes SCSI documentées seulement.
- N'envoyer au scanner que des commandes SCSI dont on connaît l'effet (comprises par la capture ou le backend SANE avision). Pas de commande de mise à jour du firmware, jamais.
- Rien installer, désinstaller, ni changer de pilote sur Medabot sans le feu vert de David. Le mode auto de Claude Code bloque `winget install` : c'est David qui lance les installations.
- Le logiciel Brother (service Mobile_Series, TWAIN, NvUSBScan.dll) reste en place tant qu'il sert de référence ; son retrait se décide avec David.
- Les captures USB brutes (.pcapng) contiennent des images de documents : ne pas les committer, les garder hors du dépôt (`captures/` est ignoré).
