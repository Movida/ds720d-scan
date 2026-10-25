/*
 * permis.h : la barrière des commandes observées (CLAUDE.md, « Sécurité
 * matérielle » ; docs/pilote.md, § 2).
 *
 * Une seule liste de ce qui a le droit de partir vers le scanner, partagée par
 * l'outil en espace utilisateur (tunnel.c) et par le pilote noyau
 * (noyau/ioctl.c, étape 6e) : un ajout se fait en un seul endroit, avec la trame
 * qui le justifie, et les deux côtés le voient. Dans le pilote, c'est le
 * dernier mot : aucun programme ne peut le contourner.
 *
 * Du C pur, sans en-tête du système : le même fichier se compile pour le noyau
 * (cl /kernel, en-têtes km\crt, qui n'ont pas stdint.h) et pour l'espace
 * utilisateur, et se teste hors ligne (essai_permis.exe). D'où unsigned char et
 * unsigned int (8 et 32 bits avec MSVC sous Windows) plutôt que uint8_t et
 * uint32_t. Chaque fonction renvoie 1 si la requête est permise, 0 sinon.
 */
#ifndef DS720D_PERMIS_H
#define DS720D_PERMIS_H

/* Transfert de contrôle : les 8 octets du paquet SETUP doivent être, à l'octet
 * près, l'un de ceux que Windows envoie au scanner dans 1b (trames 19191 à
 * 19223) : descripteurs DEVICE, CONFIGURATION, STRING 0 et GET_MAX_LUN. Pas le
 * descripteur du numéro de série (CLAUDE.md). */
int permis_controle(const unsigned char setup[8]);

/* Lecture par le tunnel 0xC5 : sélecteur (octets 10 à 12 du CDB) et longueur,
 * tels qu'observés (docs/protocole.md §2). */
int permis_lecture_c5(const unsigned char selecteur[3], unsigned int lg);

/* Dépôt par le tunnel 0xC5 (sélecteur 02 03 00) : lg octets identiques, octet
 * pour octet, à un dépôt observé (docs/protocole.md §3). */
int permis_depot_c5(const unsigned char *depot, unsigned int lg);

/* Commande Bulk-Only complète, telle qu'elle partirait dans un CBW : CDB de
 * lg_cdb octets, sens (sortant : 1 si les données vont vers le scanner),
 * dCBWDataTransferLength lg, et les données sortantes s'il y en a. Permis
 * seulement :
 *   - INQUIRY standard, le CDB de Windows en 1b (trame 19225), 36 octets lus ;
 *   - 0xC5 de 16 octets à la forme observée, en lecture d'un sélecteur permis,
 *     ou en dépôt d'un dépôt permis (sélecteur 02 03 00) ;
 *   - 0xC3 de 16 octets à la forme observée, en lecture de 1 à 65 536 octets.
 * La longueur portée par le CDB (octets 6 à 9 de 0xC5 et 0xC3) doit égaler lg. */
int permis_bot(const unsigned char *cdb, unsigned int lg_cdb, int sortant, unsigned int lg,
               const unsigned char *donnees_sortantes);

#endif
