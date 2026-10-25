/*
 * essai_bot.c : banc d'essai du transport Bulk-Only (bot.c), sans scanner.
 *
 * bot.c est lié ici à un faux périphérique : les fonctions de peripherique.h
 * sont remplacées par des bouchons qui jouent le rôle du scanner (ils renvoient
 * la réponse INQUIRY de 1b et un CSW fabriqué à la demande, et peuvent simuler
 * un STALL). On vérifie ainsi les garde-fous de bot.c sans rien envoyer sur le
 * câble :
 *   - un opcode hors liste blanche est refusé avant tout transfert ;
 *   - un CSW au mauvais tag, au résidu trop grand, au statut 2 ou au statut
 *     inconnu est rejeté (BOT §6.3.1, §6.3.2, §5.3.4), avec Reset Recovery ;
 *   - un STALL pendant les données ou sur le CSW est repris comme le veut la
 *     spec (BOT §6.7.2, §5.3.3) ;
 *   - un INQUIRY correct passe ;
 *   - une commande sortante envoie CBW puis données, et un STALL des données
 *     sortantes débloque l'endpoint OUT (BOT §6.7.3) ;
 *   - tunnel.c refuse un dépôt absent de sa liste avant tout transfert, et
 *     déroule la chorégraphie de 2a pour un dépôt permis.
 * La Reset Recovery est contrôlée octet par octet : Bulk-Only Mass Storage
 * Reset (21 ff 00 00 <interface> 00 00 00, BOT §3.1), puis déblocage de
 * l'endpoint IN, puis de l'endpoint OUT (BOT §5.3.4).
 * Code de sortie : 0 si tous les cas se comportent comme prévu.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "bot.h"
#include "peripherique.h"
#include "trace.h"
#include "tunnel.h"

#define INTERFACE 0x00
#define EP_IN 0x81
#define EP_OUT 0x02

/* Comportement du faux scanner pour le cas en cours, et ce qu'il a vu. */
static struct {
    int ecritures, lectures;   /* transferts bulk demandés à ce jour */
    uint32_t tag_recu;         /* dCBWTag du dernier CBW reçu */
    int decalage_tag;          /* ajouté au tag renvoyé dans le CSW */
    uint32_t residu;
    uint8_t statut;
    int stall_donnees;         /* STALL à la lecture des données */
    int stall_csw;             /* nombre de lectures de CSW qui finissent en STALL */
    int stall_sortie;          /* STALL à l'envoi des données sortantes */
    uint8_t opcode;            /* opcode du dernier CBW reçu */
    int signature;             /* le dernier CBW lit la signature (sélecteur ff 02 00) */
    int sondage_04;            /* le dernier CBW lit le sondage ff 04 00 */
    int occupe;                /* nombre de sondages ff 04 qui répondront « occupé » */
    int donnees_sortantes;     /* octets de données reçus de l'hôte */
    char journal[256];         /* reprises vues : « R » reset de classe, « I » / « O » déblocages */
    int reset_conforme;        /* le SETUP du reset de classe était le bon */
} faux;

/* Réponse INQUIRY de 1b, trame 19228. */
static const uint8_t inquiry[36] = {
    0x00, 0x80, 0x05, 0x02, 0x20, 0x00, 0x00, 0x00, 'B', 'r', 'o', 't', 'h', 'e', 'r', ' ',
    'D',  'S',  '-',  '7',  '2',  '0',  'D',  ' ',  ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    '0',  '.',  '2',  '7',
};

long periph_controle(const uint8_t setup[8], uint8_t *donnees)
{
    static const uint8_t reset[8] = {0x21, 0xFF, 0x00, 0x00, INTERFACE, 0x00, 0x00, 0x00};
    (void)donnees;
    strcat_s(faux.journal, sizeof faux.journal, "R");
    faux.reset_conforme = memcmp(setup, reset, 8) == 0;
    return 0;
}

int periph_debloquer(uint8_t endpoint)
{
    strcat_s(faux.journal, sizeof faux.journal, endpoint == EP_IN ? "I" : endpoint == EP_OUT ? "O" : "?");
    return 0;
}

long periph_bulk_ecrire(uint8_t endpoint, const uint8_t *donnees, size_t lg, unsigned long *erreur)
{
    (void)endpoint;
    if (lg == 31 && memcmp(donnees, "USBC", 4) == 0) {
        faux.ecritures++;
        faux.tag_recu = (uint32_t)donnees[4] | (uint32_t)donnees[5] << 8 | (uint32_t)donnees[6] << 16 |
                        (uint32_t)donnees[7] << 24;
        faux.opcode = donnees[15];
        faux.signature = donnees[15 + 10] == 0xFF && donnees[15 + 11] == 0x02;
        faux.sondage_04 = donnees[15 + 10] == 0xFF && donnees[15 + 11] == 0x04;
        return (long)lg;
    }
    if (faux.stall_sortie) {
        if (erreur)
            *erreur = ERROR_GEN_FAILURE;
        return -1;
    }
    faux.donnees_sortantes += (int)lg;
    return (long)lg;
}

long periph_bulk_lire(uint8_t endpoint, uint8_t *donnees, size_t lg, unsigned long *erreur)
{
    (void)endpoint;
    faux.lectures++;
    if (lg == 13) { /* le CSW */
        if (faux.stall_csw > 0) {
            faux.stall_csw--;
            if (erreur)
                *erreur = ERROR_GEN_FAILURE; /* ce que WinUSB rend sur un STALL */
            return -1;
        }
        uint32_t tag = faux.tag_recu + (uint32_t)faux.decalage_tag;
        uint8_t csw[13] = {0x55, 0x53, 0x42, 0x53, (uint8_t)tag, (uint8_t)(tag >> 8), (uint8_t)(tag >> 16),
                           (uint8_t)(tag >> 24), (uint8_t)faux.residu, (uint8_t)(faux.residu >> 8),
                           (uint8_t)(faux.residu >> 16), (uint8_t)(faux.residu >> 24), faux.statut};
        memcpy(donnees, csw, 13);
        return 13;
    }
    if (faux.stall_donnees) {
        if (erreur)
            *erreur = ERROR_GEN_FAILURE;
        return -1;
    }
    if (faux.opcode == 0xC5) { /* tunnel : « NOVA » pour la signature (ff 02 00), des zéros sinon */
        memset(donnees, 0, lg);
        if (lg == 16 && faux.sondage_04 && faux.occupe > 0)
            faux.occupe--;     /* sondage ff 04 : « occupé » (octet 8 à 0), comme après RELEASE en 2a */
        else if (lg == 16)
            donnees[8] = 0x01; /* sondage : « prêt », sans quoi tunnel.c attendrait */
        if (lg == 4 && faux.signature)
            memcpy(donnees, "NOVA", 4);
        return (long)lg;
    }
    memcpy(donnees, inquiry, lg < sizeof inquiry ? lg : sizeof inquiry);
    return (long)(lg < sizeof inquiry ? lg : sizeof inquiry);
}

/* Réglages d'un cas. */
struct reglages {
    int decalage_tag;
    uint32_t residu;
    uint8_t statut;
    int stall_donnees, stall_csw;
};

/* Un cas : opcode, réglages du faux scanner, résultat attendu de bot_commande_in,
 * nombre de CBW envoyés, et suite de reprises attendue (« RIO » : Reset Recovery
 * complète ; « I » : déblocage de l'endpoint IN seul ; « » : aucune). */
static int cas(const char *nom, uint8_t opcode, struct reglages g, int attendu, int ecritures_attendues,
               const char *reprises_attendues)
{
    uint8_t cdb[6] = {opcode, 0x00, 0x00, 0x00, 0x24, 0x00};
    uint8_t d[36];
    struct bot_resultat r;
    memset(&faux, 0, sizeof faux);
    faux.decalage_tag = g.decalage_tag;
    faux.residu = g.residu;
    faux.statut = g.statut;
    faux.stall_donnees = g.stall_donnees;
    faux.stall_csw = g.stall_csw;
    trace_note("cas : %s", nom);
    int obtenu = bot_commande_in(0, cdb, sizeof cdb, d, sizeof d, &r);
    int bon = obtenu == attendu && faux.ecritures == ecritures_attendues &&
              strcmp(faux.journal, reprises_attendues) == 0 && (!strchr(faux.journal, 'R') || faux.reset_conforme);
    printf("%s  %s (retour %d, %d CBW envoyé(s), reprises « %s »)\n", bon ? "OK   " : "ÉCHEC", nom, obtenu,
           faux.ecritures, faux.journal);
    return bon;
}

/* Commande sortante de 10 octets : CBW, données, CSW. */
static int cas_sortant(const char *nom, int stall, int attendu, const char *reprises_attendues)
{
    static const uint8_t cdb[16] = {0xC5, 0x07, 0, 0, 0, 0, 0, 0, 0, 10, 0x02, 0x03, 0x00};
    static const uint8_t depot[10] = {0x08, 0, 0, 0, 0x02};
    struct bot_resultat r;
    memset(&faux, 0, sizeof faux);
    faux.stall_sortie = stall;
    trace_note("cas : %s", nom);
    int obtenu = bot_commande_out(0, cdb, sizeof cdb, depot, sizeof depot, &r);
    int bon = obtenu == attendu && faux.ecritures == 1 && faux.donnees_sortantes == (stall ? 0 : 10) &&
              strcmp(faux.journal, reprises_attendues) == 0;
    printf("%s  %s (retour %d, %d o de données, reprises « %s »)\n", bon ? "OK   " : "ÉCHEC", nom, obtenu,
           faux.donnees_sortantes, faux.journal);
    return bon;
}

/* Dépôt par tunnel.c : refusé avant tout envoi s'il n'est pas dans la liste ;
 * sinon, nombre de CBW de la chorégraphie de 2a (trames 781 à 934) : 4
 * sondages, le dépôt, 2 sondages, puis deux lectures de réponse de 9 CBW
 * chacune (4 sondages, en-tête, sondage, réponse, 2 sondages). */
static int cas_depot(const char *nom, const uint8_t *depot, uint32_t lg, uint32_t lg_reponse, int occupe,
                     int attendu, int cbw_attendus)
{
    uint8_t reponse[2];
    memset(&faux, 0, sizeof faux);
    faux.occupe = occupe;
    trace_note("cas : %s", nom);
    int obtenu = tunnel_commande(depot, lg, reponse, lg_reponse);
    int bon = obtenu == attendu && faux.ecritures == cbw_attendus;
    printf("%s  %s (retour %d, %d CBW envoyé(s))\n", bon ? "OK   " : "ÉCHEC", nom, obtenu, faux.ecritures);
    return bon;
}

int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    trace_ouvrir(NULL);
    bot_init(INTERFACE, EP_IN, EP_OUT);
    const struct reglages normal = {0, 0, 0, 0, 0};
    int bons = 0, total = 0;
    total++, bons += cas("INQUIRY correct", 0x12, normal, 0, 1, "");
    total++, bons += cas("WRITE(10) 0x2A refusé avant envoi", 0x2A, normal, -1, 0, "");
    total++, bons += cas("FORMAT UNIT 0x04 refusé avant envoi", 0x04, normal, -1, 0, "");
    total++, bons += cas("WRITE BUFFER 0x3B (firmware) refusé avant envoi", 0x3B, normal, -1, 0, "");
    total++, bons += cas("vendeur 0xC5 admis (étape 3c)", 0xC5, normal, 0, 1, "");
    total++, bons += cas("CSW au mauvais tag rejeté, Reset Recovery", 0x12, (struct reglages){1, 0, 0, 0, 0}, -1,
                         1, "RIO");
    total++, bons += cas("CSW au résidu > attendu rejeté, Reset Recovery", 0x12,
                         (struct reglages){0, 37, 0, 0, 0}, -1, 1, "RIO");
    total++, bons += cas("CSW statut 2 (erreur de phase), Reset Recovery", 0x12,
                         (struct reglages){0, 0, 2, 0, 0}, -1, 1, "RIO");
    total++, bons += cas("CSW statut 3 (inconnu) rejeté, Reset Recovery", 0x12,
                         (struct reglages){0, 0, 3, 0, 0}, -1, 1, "RIO");
    total++, bons += cas("CSW statut 1 (échec) rendu à l'appelant", 0x12, (struct reglages){0, 0, 1, 0, 0}, 0, 1,
                         "");
    total++, bons += cas("STALL des données : déblocage IN puis CSW lu", 0x12,
                         (struct reglages){0, 36, 1, 1, 0}, 0, 1, "I");
    total++, bons += cas("STALL du CSW une fois : déblocage IN et CSW relu", 0x12,
                         (struct reglages){0, 0, 0, 0, 1}, 0, 1, "I");
    total++, bons += cas("STALL du CSW deux fois : Reset Recovery", 0x12, (struct reglages){0, 0, 0, 0, 2}, -1,
                         1, "IRIO");
    total++, bons += cas_sortant("commande sortante : CBW puis 10 o de données", 0, 0, "");
    total++, bons += cas_sortant("STALL des données sortantes : déblocage OUT puis CSW", 1, 0, "O");
    static const uint8_t papier[10] = {0x08, 0, 0, 0, 0x02};
    static const uint8_t papier_faux[10] = {0x08, 0, 0, 0, 0x03}; /* un octet de différence */
    static const uint8_t send95[12] = {0x2a, 0, 0x95, 0, 0, 0x01, 0, 0, 0x02};
    /* Les octets de Capture Tool (00 78, 1e-gris-300-recto) au lieu de ceux de TWAIN. */
    static const uint8_t send95_ct[12] = {0x2a, 0, 0x95, 0, 0, 0x01, 0, 0, 0x02, 0, 0, 0x78};
    total++, bons += cas_depot("dépôt 0x08 de 2a accepté, 25 CBW", papier, sizeof papier, 2, 0, 0, 25);
    /* Le premier ff 04 « occupé » tombe dans les sondages d'avant le dépôt, que
     * tunnel.c ne fait pas attendre (aucune capture n'y montre un 0) ; le second,
     * après le dépôt, est relu une fois : 26 CBW au lieu de 25. */
    total++, bons += cas_depot("scanner occupé après le dépôt : ff 04 relu, 26 CBW", papier, sizeof papier, 2, 2, 0,
                               26);
    total++, bons += cas_depot("dépôt 0x08 altéré d'un octet refusé", papier_faux, sizeof papier_faux, 2, 0, -1, 0);
    /* SEND ne rend pas de données : dépôt et statut seulement, 7 + 9 = 16 CBW. */
    total++, bons += cas_depot("dépôt SEND 0x95 de 2a accepté (étape 3e), 16 CBW", send95, sizeof send95, 0, 0, 0,
                               16);
    total++, bons += cas_depot("dépôt SEND 0x95 de Capture Tool refusé", send95_ct, sizeof send95_ct, 0, 0, -1, 0);
    trace_fermer();
    printf("%d/%d cas conformes\n", bons, total);
    return bons == total ? 0 : 1;
}
