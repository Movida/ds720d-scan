/*
 * tunnel.h : la commande vendeur 0xC5 du DS-720D (docs/protocole.md §1 et §2).
 *
 * 0xC5 est un tunnel : son CDB de 16 octets porte un sélecteur de trois octets
 * qui dit quoi lire (signature, sondage d'état, réponse) ou, plus tard, quoi
 * déposer (une commande de scanner SCSI-2 emballée). Ce module construit le CDB
 * octet par octet et le confie au transport Bulk-Only (bot.c).
 *
 * Il ne laisse passer que les sélecteurs observés dans les captures, comme bot.c
 * ne laisse passer que les opcodes observés : deux garde-fous, à deux niveaux.
 */
#ifndef DS720D_TUNNEL_H
#define DS720D_TUNNEL_H

#include <stdint.h>

#include "bot.h"

/* Lecture par le tunnel : sélecteur selecteur[0..2], lg octets attendus.
 * Renvoie 0 si la commande a abouti avec un statut CSW 0 et exactement lg
 * octets reçus, -1 sinon (le détail est sur stderr et dans la trace). */
int tunnel_lire(const uint8_t selecteur[3], uint8_t *donnees, uint32_t lg);

#endif
