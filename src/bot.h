/*
 * bot.h : transport USB Mass Storage Bulk-Only (BOT 1.0).
 *
 * Une commande SCSI voyage en trois temps (BOT §5) :
 *   1. le CBW (Command Block Wrapper, 31 octets) part sur l'endpoint bulk OUT ;
 *   2. les données éventuelles passent sur l'endpoint bulk IN ou OUT ;
 *   3. le CSW (Command Status Wrapper, 13 octets) revient sur l'endpoint bulk IN.
 * Ce module construit le CBW octet par octet, lit et contrôle le CSW, et trace
 * les trois temps. Il ne connaît pas SCSI : le CDB lui est fourni tout fait.
 */
#ifndef DS720D_BOT_H
#define DS720D_BOT_H

#include <stddef.h>
#include <stdint.h>

/* Endpoints bulk lus dans les descripteurs, à fournir avant toute commande. */
void bot_init(uint8_t ep_in, uint8_t ep_out);

/* Résultat d'une commande dont le CSW a été lu et reconnu valide (BOT §6.3). */
struct bot_resultat {
    uint8_t statut;     /* bCSWStatus : 0 réussite, 1 échec, 2 erreur de phase */
    uint32_t residu;    /* dCSWDataResidue : octets attendus mais non transférés */
    size_t recus;       /* octets de données effectivement reçus */
};

/* Commande entrante (données de l'appareil vers l'hôte) de lg octets au plus.
 * Renvoie 0 si le CSW est valide (son statut est dans *r), -1 sinon. */
int bot_commande_in(uint8_t lun, const uint8_t *cdb, uint8_t lg_cdb,
                    uint8_t *donnees, uint32_t lg, struct bot_resultat *r);

#endif
