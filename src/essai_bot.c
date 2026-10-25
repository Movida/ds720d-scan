/*
 * essai_bot.c : banc d'essai du transport Bulk-Only (bot.c), sans scanner.
 *
 * bot.c est lié ici à un faux périphérique : les deux fonctions bulk de
 * peripherique.h sont remplacées par des bouchons qui jouent le rôle du scanner
 * (ils renvoient la réponse INQUIRY de 1b et un CSW fabriqué à la demande). On
 * vérifie ainsi les garde-fous de bot.c sans rien envoyer sur le câble :
 *   - un opcode hors liste blanche est refusé avant tout transfert ;
 *   - un CSW au mauvais tag, au résidu trop grand, au statut 2 ou au statut
 *     inconnu est rejeté (BOT §6.3.1, §6.3.2, §5.3.4) ;
 *   - un INQUIRY correct passe.
 * Code de sortie : 0 si tous les cas se comportent comme prévu.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "bot.h"
#include "peripherique.h"
#include "trace.h"

/* Comportement du faux scanner pour le cas en cours. */
static struct {
    int ecritures, lectures;   /* transferts demandés à ce jour */
    uint32_t tag_recu;         /* dCBWTag du dernier CBW reçu */
    int decalage_tag;          /* ajouté au tag renvoyé dans le CSW */
    uint32_t residu;
    uint8_t statut;
} faux;

/* Réponse INQUIRY de 1b, trame 19228. */
static const uint8_t inquiry[36] = {
    0x00, 0x80, 0x05, 0x02, 0x20, 0x00, 0x00, 0x00, 'B', 'r', 'o', 't', 'h', 'e', 'r', ' ',
    'D',  'S',  '-',  '7',  '2',  '0',  'D',  ' ',  ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    '0',  '.',  '2',  '7',
};

long periph_bulk_ecrire(uint8_t endpoint, const uint8_t *donnees, size_t lg, unsigned long *erreur)
{
    (void)endpoint;
    (void)erreur;
    faux.ecritures++;
    if (lg == 31)
        faux.tag_recu = (uint32_t)donnees[4] | (uint32_t)donnees[5] << 8 | (uint32_t)donnees[6] << 16 |
                        (uint32_t)donnees[7] << 24;
    return (long)lg;
}

long periph_bulk_lire(uint8_t endpoint, uint8_t *donnees, size_t lg, unsigned long *erreur)
{
    (void)endpoint;
    (void)erreur;
    faux.lectures++;
    if (lg == 13) { /* le CSW */
        uint32_t tag = faux.tag_recu + (uint32_t)faux.decalage_tag;
        uint8_t csw[13] = {0x55, 0x53, 0x42, 0x53, (uint8_t)tag, (uint8_t)(tag >> 8), (uint8_t)(tag >> 16),
                           (uint8_t)(tag >> 24), (uint8_t)faux.residu, (uint8_t)(faux.residu >> 8),
                           (uint8_t)(faux.residu >> 16), (uint8_t)(faux.residu >> 24), faux.statut};
        memcpy(donnees, csw, 13);
        return 13;
    }
    memcpy(donnees, inquiry, lg < sizeof inquiry ? lg : sizeof inquiry);
    return (long)(lg < sizeof inquiry ? lg : sizeof inquiry);
}

/* Un cas : CDB, réglages du faux scanner, résultat attendu de bot_commande_in. */
static int cas(const char *nom, uint8_t opcode, int decalage_tag, uint32_t residu, uint8_t statut,
               int attendu, int ecritures_attendues)
{
    uint8_t cdb[6] = {opcode, 0x00, 0x00, 0x00, 0x24, 0x00};
    uint8_t d[36];
    struct bot_resultat r;
    memset(&faux, 0, sizeof faux);
    faux.decalage_tag = decalage_tag;
    faux.residu = residu;
    faux.statut = statut;
    trace_note("cas : %s", nom);
    int obtenu = bot_commande_in(0, cdb, sizeof cdb, d, sizeof d, &r);
    int bon = obtenu == attendu && faux.ecritures == ecritures_attendues;
    printf("%s  %s (retour %d, %d CBW envoyé(s))\n", bon ? "OK   " : "ÉCHEC", nom, obtenu, faux.ecritures);
    return bon;
}

int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    trace_ouvrir(NULL);
    bot_init(0x81, 0x02);
    int bons = 0, total = 0;
    total++, bons += cas("INQUIRY correct", 0x12, 0, 0, 0, 0, 1);
    total++, bons += cas("WRITE(10) 0x2A refusé avant envoi", 0x2A, 0, 0, 0, -1, 0);
    total++, bons += cas("FORMAT UNIT 0x04 refusé avant envoi", 0x04, 0, 0, 0, -1, 0);
    total++, bons += cas("vendeur 0xC5 refusé (pas encore dans la liste)", 0xC5, 0, 0, 0, -1, 0);
    total++, bons += cas("CSW au mauvais tag rejeté", 0x12, 1, 0, 0, -1, 1);
    total++, bons += cas("CSW au résidu > attendu rejeté", 0x12, 0, 37, 0, -1, 1);
    total++, bons += cas("CSW statut 2 (erreur de phase) rejeté", 0x12, 0, 0, 2, -1, 1);
    total++, bons += cas("CSW statut 3 (inconnu) rejeté", 0x12, 0, 0, 3, -1, 1);
    total++, bons += cas("CSW statut 1 (échec) rendu à l'appelant", 0x12, 0, 0, 1, 0, 1);
    trace_fermer();
    printf("%d/%d cas conformes\n", bons, total);
    return bons == total ? 0 : 1;
}
