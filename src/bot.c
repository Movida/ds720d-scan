/*
 * bot.c : CBW, données et CSW du transport Bulk-Only (BOT 1.0, §5 et §6).
 *
 * Pourquoi tout écrire à la main : c'est exactement ce que fait USBSTOR pour le
 * disque F:, et ce que la passation demande de voir de près (le SCSI pass-through
 * de Windows le cacherait). Les 31 octets du CBW sont posés un par un, dans
 * l'ordre de BOT §5.1, table 5.1.
 *
 * Les deux sens existent : entrant (INQUIRY, lectures du tunnel 0xC5) et, depuis
 * l'étape 3d, sortant (dépôt d'une commande dans le tunnel).
 *
 * Reprise sur erreur (étape 3c), selon BOT §5.3 et §6.7 :
 *   - STALL pendant les données : on débloque l'endpoint IN et on lit le CSW
 *     quand même (BOT §6.7.2) ;
 *   - STALL à la lecture du CSW : on débloque et on réessaie une fois (BOT §5.3.3,
 *     figure 2) ;
 *   - CBW refusé, CSW invalide ou non significatif, erreur de phase, appareil
 *     muet : Reset Recovery (BOT §5.3.4), puis la commande échoue.
 * Aucune de ces situations n'apparaît dans les captures du pilote Brother : la
 * reprise ne s'appuie que sur la spec (CLAUDE.md : commande documentée).
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

static uint8_t ep_in, ep_out, interface_bot;

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
    0xC5, /* tunnel vendeur, 1b trame 20841, 2a trame 772 ; les sélecteurs permis
           * sont filtrés à leur tour par tunnel.c */
    0xC3, /* lecture du tampon d'image, 2a trame 52325 (étape 3e) */
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

void bot_init(uint8_t interface, uint8_t in, uint8_t out)
{
    LARGE_INTEGER t;
    interface_bot = interface;
    ep_in = in;
    ep_out = out;
    /* Le compteur de performances change à chaque exécution : bon point de départ
     * pour les tags, sans prétention d'aléa. */
    QueryPerformanceCounter(&t);
    prochain_tag = (uint32_t)t.QuadPart;
}

/* WinUSB rend ERROR_GEN_FAILURE quand l'appareil répond par un STALL (le code
 * USBD_STATUS_STALL_PID du pilote de bus, traduit en Win32). */
static int est_stall(unsigned long erreur) { return erreur == ERROR_GEN_FAILURE; }

int bot_reprise(void)
{
    /* Reset Recovery, BOT §5.3.4, trois temps dans cet ordre.
     * (a) Bulk-Only Mass Storage Reset, requête de classe (BOT §3.1) :
     *     bmRequestType 0x21 (hôte vers appareil, classe, destinataire l'interface),
     *     bRequest 0xFF, wValue 0, wIndex numéro d'interface, wLength 0.
     *     L'appareil se remet prêt à recevoir un CBW, sans toucher à ses données. */
    uint8_t s[8] = {0x21, 0xFF, 0x00, 0x00, interface_bot, 0x00, 0x00, 0x00};
    int r = 0;
    trace_note("Reset Recovery (BOT §5.3.4)");
    if (periph_controle(s, NULL) < 0)
        r = -1;
    /* (b) puis (c) : Clear Feature HALT sur bulk IN, puis sur bulk OUT. On les
     * tente même si (a) a échoué : c'est ce qui reste pour débloquer le transport. */
    if (periph_debloquer(ep_in) != 0)
        r = -1;
    if (periph_debloquer(ep_out) != 0)
        r = -1;
    if (r)
        fprintf(stderr, "Reset Recovery incomplète : débrancher et rebrancher le scanner\n");
    return r;
}

/* Lit le CSW ; sur un STALL, débloque l'endpoint et réessaie une seule fois
 * (BOT §5.3.3 et figure 2 « Status Transport Flow »). Renvoie le nombre d'octets
 * lus, ou -1. */
static long lire_csw(uint8_t csw[LG_CSW])
{
    unsigned long erreur = 0;
    long n = periph_bulk_lire(ep_in, csw, LG_CSW, &erreur);
    if (n < 0 && est_stall(erreur) && periph_debloquer(ep_in) == 0)
        n = periph_bulk_lire(ep_in, csw, LG_CSW, NULL);
    return n;
}

/* Une commande dans un sens ou dans l'autre : les deux ne diffèrent que par le
 * bit 7 de bmCBWFlags et l'endpoint de la phase de données (BOT §5.1, §6.7). */
static int commande(uint8_t lun, const uint8_t *cdb, uint8_t lg_cdb, int sortant,
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
    cbw[12] = sortant ? 0x00 : 0x80;   /* bmCBWFlags : bit 7 à 1, données vers l'hôte */
    cbw[13] = lun;                     /* bCBWLUN (bits 3..0) */
    cbw[14] = lg_cdb;                  /* bCBWCBLength (bits 4..0) */
    memcpy(cbw + 15, cdb, lg_cdb);     /* CBWCB, complété de zéros jusqu'à 16 octets */

    trace_cbw(cbw);
    if (periph_bulk_ecrire(ep_out, cbw, LG_CBW, NULL) != LG_CBW) {
        /* CBW refusé (STALL de l'endpoint OUT) ou perdu : BOT §6.6.1 demande une
         * Reset Recovery avant toute nouvelle commande. */
        fprintf(stderr, "envoi du CBW impossible\n");
        bot_reprise();
        return -1;
    }

    /* 2. Données. Un STALL ici est légal (BOT §6.7.2 en entrée : l'appareil a
     * moins à envoyer que demandé ; §6.7.3 en sortie : il refuse la suite) : on
     * débloque l'endpoint concerné et on passe au CSW, qui dira le statut et le
     * résidu. Tout autre échec (délai dépassé, câble) laisse le transport dans un
     * état inconnu : Reset Recovery. Les données sortantes sont tracées au
     * départ, les entrantes à l'arrivée, comme les voit USBPcap. */
    r->recus = 0;
    if (lg) {
        unsigned long erreur = 0;
        uint8_t ep = sortant ? ep_out : ep_in;
        if (sortant) {
            trace_data_out(donnees, lg);
            n = periph_bulk_ecrire(ep, donnees, lg, &erreur);
        } else {
            n = periph_bulk_lire(ep, donnees, lg, &erreur);
        }
        if (n < 0 && !(est_stall(erreur) && periph_debloquer(ep) == 0)) {
            fprintf(stderr, "%s des données impossible (Win32=%lu), arrêt\n", sortant ? "envoi" : "lecture",
                    erreur);
            bot_reprise();
            return -1;
        }
        if (n > 0) {
            r->recus = (size_t)n;
            if (!sortant)
                trace_data_in(donnees, r->recus);
        }
    }

    /* 3. CSW, BOT §5.2, table 5.2 ; validité selon BOT §6.3.1 : 13 octets, la
     * signature 'USBS' et le tag du CBW. Un CSW invalide impose une Reset
     * Recovery (BOT §5.3.3). */
    n = lire_csw(csw);
    if (n < 0) {
        fprintf(stderr, "lecture du CSW impossible, arrêt\n");
        bot_reprise();
        return -1;
    }
    if (n != LG_CSW) {
        trace_data_in(csw, (size_t)n);
        fprintf(stderr, "CSW de %ld octets au lieu de 13 : invalide (BOT §6.3.1)\n", n);
        bot_reprise();
        return -1;
    }
    trace_csw(csw);
    if (le32(csw) != SIGNATURE_CSW || le32(csw + 4) != tag) {
        fprintf(stderr, "CSW invalide : signature ou tag faux (BOT §6.3.1)\n");
        bot_reprise();
        return -1;
    }
    r->residu = le32(csw + 8); /* dCSWDataResidue */
    r->statut = csw[12];       /* bCSWStatus, table 5.3 */

    /* CSW « significatif » (BOT §6.3.2) : statut 0, 1 ou 2, et un résidu qui ne
     * dépasse pas ce qu'annonçait le CBW. Le DS-720D peut violer la seconde règle :
     * après une commande à résidu non nul, il répète ce résidu dans le CSW des
     * 0xC5 suivantes (protocole.md §1, « résidu collé », vu sous USBSTOR après un
     * MODE SENSE de Windows). Nos commandes n'en laissant pas, on garde la règle de
     * la spec plutôt qu'une tolérance qui masquerait d'autres erreurs. */
    if (r->statut > 2 || r->residu > lg) {
        fprintf(stderr, "CSW non significatif : statut %u, résidu %u pour %u attendus (BOT §6.3.2)\n",
                r->statut, r->residu, lg);
        bot_reprise();
        return -1;
    }
    if (r->statut == 2) {
        /* Erreur de phase : l'appareil exige une Reset Recovery (BOT §5.3.4). */
        fprintf(stderr, "CSW : erreur de phase, Reset Recovery (BOT §5.3.4)\n");
        bot_reprise();
        return -1;
    }
    return 0;
}

int bot_commande_in(uint8_t lun, const uint8_t *cdb, uint8_t lg_cdb,
                    uint8_t *donnees, uint32_t lg, struct bot_resultat *r)
{
    return commande(lun, cdb, lg_cdb, 0, donnees, lg, r);
}

int bot_commande_out(uint8_t lun, const uint8_t *cdb, uint8_t lg_cdb,
                     const uint8_t *donnees, uint32_t lg, struct bot_resultat *r)
{
    /* commande() ne modifie pas un tampon sortant : il ne fait que le lire pour
     * la trace et pour WinUsb_WritePipe. */
    return commande(lun, cdb, lg_cdb, 1, (uint8_t *)donnees, lg, r);
}
