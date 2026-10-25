/*
 * bot.c : CBW, données et CSW du transport Bulk-Only (BOT 1.0, §5 et §6).
 *
 * Pourquoi tout écrire à la main : c'est exactement ce que fait USBSTOR pour le
 * disque F:, et ce que la passation demande de voir de près (le SCSI pass-through
 * de Windows le cacherait). Les 31 octets du CBW sont posés un par un, dans
 * l'ordre de BOT §5.1, table 5.1.
 *
 * Seules les commandes entrantes existent pour l'instant (INQUIRY) : on n'ajoute
 * le sens sortant que quand une commande observée en aura besoin.
 */
#include "bot.h"
#include "peripherique.h"
#include "trace.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#define SIGNATURE_CBW 0x43425355u /* 'USBC' en petit-boutiste, BOT §5.1 */
#define SIGNATURE_CSW 0x53425355u /* 'USBS' en petit-boutiste, BOT §5.2 */
#define LG_CBW 31
#define LG_CSW 13

static uint8_t ep_in, ep_out;

/* dCBWTag : valeur libre que l'appareil recopie dans le CSW (BOT §5.1), pour
 * associer chaque CSW à son CBW. Windows y met l'adresse de l'IRP (le tag
 * 0xA41D25B0 de 1b est la fin de l'IRP 0xFFFFE609A41D25B0). Nous prenons un
 * compteur, mais qui part d'une valeur différente à chaque exécution (bot_init) :
 * si une exécution précédente s'est arrêtée au milieu d'une commande, son CSW
 * resté en attente porterait un autre tag et serait rejeté (BOT §6.3.1), au lieu
 * d'être pris pour celui de notre nouvelle commande. */
static uint32_t prochain_tag;

/* Liste blanche des opcodes SCSI que ce module accepte d'envoyer (règle de
 * CLAUDE.md : seulement des commandes observées dans une capture). Elle ne
 * s'allonge que d'un opcode observé, avec la trame qui le montre. Tout le reste,
 * et en particulier ce qui écrit sur le support (WRITE, FORMAT UNIT, MODE
 * SELECT…), est refusé avant même la construction du CBW : la relecture du code
 * ne suffit pas, une erreur de copie de CDB à l'étape 3 doit être arrêtée ici. */
static const uint8_t opcodes_permis[] = {
    0x12, /* INQUIRY, 1b trame 19225 */
};

static int opcode_permis(uint8_t op)
{
    for (size_t i = 0; i < sizeof opcodes_permis; i++)
        if (opcodes_permis[i] == op)
            return 1;
    return 0;
}

static void pose_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

void bot_init(uint8_t in, uint8_t out)
{
    LARGE_INTEGER t;
    ep_in = in;
    ep_out = out;
    /* Le compteur de performances change à chaque exécution : bon point de départ
     * pour les tags, sans prétention d'aléa. */
    QueryPerformanceCounter(&t);
    prochain_tag = (uint32_t)t.QuadPart;
}

int bot_commande_in(uint8_t lun, const uint8_t *cdb, uint8_t lg_cdb,
                    uint8_t *donnees, uint32_t lg, struct bot_resultat *r)
{
    uint8_t cbw[LG_CBW] = {0}, csw[LG_CSW];
    long n;

    if (lg_cdb < 1 || lg_cdb > 16 || lun > 15) /* BOT §5.1 : CDB de 1 à 16 octets, LUN sur 4 bits */
        return -1;
    if (!opcode_permis(cdb[0])) {
        fprintf(stderr, "opcode SCSI 0x%02X refusé : absent de la liste blanche de bot.c\n", cdb[0]);
        return -1;
    }
    uint32_t tag = prochain_tag++;

    /* 1. CBW, BOT §5.1, table 5.1 */
    pose_le32(cbw + 0, SIGNATURE_CBW); /* dCBWSignature */
    pose_le32(cbw + 4, tag);           /* dCBWTag */
    pose_le32(cbw + 8, lg);            /* dCBWDataTransferLength : octets attendus */
    cbw[12] = 0x80;                    /* bmCBWFlags : bit 7 à 1, données vers l'hôte */
    cbw[13] = lun;                     /* bCBWLUN (bits 3..0) */
    cbw[14] = lg_cdb;                  /* bCBWCBLength (bits 4..0) */
    memcpy(cbw + 15, cdb, lg_cdb);     /* CBWCB, complété de zéros jusqu'à 16 octets */

    trace_cbw(cbw);
    if (periph_bulk_ecrire(ep_out, cbw, LG_CBW, NULL) != LG_CBW) {
        fprintf(stderr, "envoi du CBW impossible\n");
        return -1;
    }

    /* 2. Données. Un STALL ici serait légal (BOT §6.7.2 : l'appareil refuse de
     * fournir plus de données) ; l'hôte devrait alors effacer le blocage de
     * l'endpoint puis lire le CSW. On ne le fait pas encore : on s'arrête et on
     * le dit. Un rebranchement du scanner remet ses endpoints à zéro. */
    r->recus = 0;
    if (lg) {
        n = periph_bulk_lire(ep_in, donnees, lg, NULL);
        if (n < 0) {
            fprintf(stderr, "lecture des données impossible (STALL probable), arrêt\n");
            return -1;
        }
        r->recus = (size_t)n;
        trace_data_in(donnees, r->recus);
    }

    /* 3. CSW, BOT §5.2, table 5.2 ; validité selon BOT §6.3.1 : 13 octets, la
     * signature 'USBS' et le tag du CBW. */
    n = periph_bulk_lire(ep_in, csw, LG_CSW, NULL);
    if (n < 0) {
        fprintf(stderr, "lecture du CSW impossible, arrêt\n");
        return -1;
    }
    if (n != LG_CSW) {
        trace_data_in(csw, (size_t)n);
        fprintf(stderr, "CSW de %ld octets au lieu de 13 : invalide (BOT §6.3.1)\n", n);
        return -1;
    }
    trace_csw(csw);
    if (le32(csw) != SIGNATURE_CSW || le32(csw + 4) != tag) {
        fprintf(stderr, "CSW invalide : signature ou tag faux (BOT §6.3.1)\n");
        return -1;
    }
    r->residu = le32(csw + 8); /* dCSWDataResidue */
    r->statut = csw[12];       /* bCSWStatus, table 5.3 */

    /* CSW « significatif » (BOT §6.3.2) : statut 0, 1 ou 2, et un résidu qui ne
     * dépasse pas ce qu'annonçait le CBW. */
    if (r->statut > 2 || r->residu > lg) {
        fprintf(stderr, "CSW non significatif : statut %u, résidu %u pour %u attendus (BOT §6.3.2)\n",
                r->statut, r->residu, lg);
        return -1;
    }
    if (r->statut == 2) {
        /* Erreur de phase : l'appareil exige une Reset Recovery (BOT §5.3.4), que
         * ce module ne fait pas encore. Rebrancher le scanner en tient lieu. */
        fprintf(stderr, "CSW : erreur de phase, Reset Recovery nécessaire (BOT §5.3.4), arrêt\n");
        return -1;
    }
    return 0;
}
