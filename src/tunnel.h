/*
 * tunnel.h : les commandes vendeur 0xC5 et 0xC3 du DS-720D (docs/protocole.md).
 *
 * 0xC5 est un tunnel : son CDB de 16 octets porte un sélecteur de trois octets
 * qui dit quoi lire (signature, sondage d'état, réponse) ou, plus tard, quoi
 * déposer (une commande de scanner SCSI-2 emballée). Ce module construit le CDB
 * octet par octet et le confie au transport Bulk-Only (bot.c).
 *
 * Il ne laisse passer que les sélecteurs observés dans les captures, comme bot.c
 * ne laisse passer que les opcodes observés : deux garde-fous, à deux niveaux.
 * Il porte aussi la lecture du tampon d'image par 0xC3 (protocole.md §4).
 */
#ifndef DS720D_TUNNEL_H
#define DS720D_TUNNEL_H

#include <stdint.h>

#include "bot.h"

/* Lecture par le tunnel : sélecteur selecteur[0..2], lg octets attendus.
 * Renvoie 0 si la commande a abouti avec un statut CSW 0 et exactement lg
 * octets reçus, -1 sinon (le détail est sur stderr et dans la trace). */
int tunnel_lire(const uint8_t selecteur[3], uint8_t *donnees, uint32_t lg);

/* Signature (sélecteur ff 02 00) : 0 si le scanner répond « NOVA ». */
int tunnel_signature(void);

/* Commande SCSI-2 emballée, avec la chorégraphie du pilote Brother (2a, trames
 * 781 à 934) : sondages, dépôt de lg_depot octets (sélecteur 02 03 00),
 * sondages, lecture de lg_reponse octets de réponse s'il y en a (k = 0), puis
 * du statut (k = 1), qui doit être nul. Le dépôt doit être identique, octet
 * pour octet, à un dépôt observé (liste de permis.c). Renvoie 0 ou -1. */
int tunnel_commande(const uint8_t *depot, uint32_t lg_depot, uint8_t *reponse, uint32_t lg_reponse);

/* Les trois temps de tunnel_commande, séparément, pour la boucle de lecture
 * d'image (protocole.md §4), où le pilote Brother ne lit le statut de READ
 * qu'après avoir lu le bloc, et pas du tout après le dernier. */
int tunnel_deposer(const uint8_t *depot, uint32_t lg_depot);
int tunnel_statut(void);

/* État du bloc d'image (réponse 02 02 02, protocole.md §4). */
struct etat_bloc {
    uint32_t etat;               /* 0 pas prêt, 1 prêt, 3 fin de page */
    unsigned long long volume;   /* octets du bloc, produit des mots 3 et 4 */
    uint32_t adresse;            /* adresse du bloc dans la mémoire du scanner */
};
int tunnel_etat_bloc(struct etat_bloc *b);

/* Lecture de lg octets à l'adresse donnée par la commande vendeur 0xC3. */
int tampon_lire(uint32_t adresse, uint8_t *donnees, uint32_t lg);

#endif
