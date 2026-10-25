/*
 * tunnel.c : la commande vendeur 0xC5 (docs/protocole.md §2).
 *
 * Forme du CDB, identique dans les 17 captures de référence (protocole.md §1) :
 *   octet 0      0xC5, code d'opération du groupe 6, réservé aux fabricants
 *                (SCSI-2 §7.2.1)
 *   octet 1      0x07, constant, sens inconnu
 *   octets 2-5   0 (l'adresse ne sert qu'à 0xC3)
 *   octets 6-9   longueur des données, gros-boutiste, égale à celle du CBW
 *   octets 10-12 sélecteur
 *   octets 13-15 0
 *
 * Deux garde-fous, en plus de la liste blanche d'opcodes de bot.c :
 *   - en lecture, seuls les sélecteurs observés partent ;
 *   - en dépôt, seuls partent des dépôts identiques, octet pour octet, à un
 *     dépôt observé. Un dépôt transmet une commande au scanner : une erreur de
 *     copie d'un seul octet (une longueur, un type de données) doit être
 *     arrêtée ici, pas découverte sur le matériel.
 */
#include "tunnel.h"
#include "permis.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

/* Les listes de lectures et de dépôts permis sont dans permis.c depuis
 * l'étape 6e : le pilote noyau applique la même (src/permis.h). */

static void cdb_tunnel(uint8_t cdb[16], const uint8_t selecteur[3], uint32_t lg)
{
    memset(cdb, 0, 16);
    cdb[0] = 0xC5;
    cdb[1] = 0x07;
    cdb[6] = (uint8_t)(lg >> 24); /* longueur, gros-boutiste */
    cdb[7] = (uint8_t)(lg >> 16);
    cdb[8] = (uint8_t)(lg >> 8);
    cdb[9] = (uint8_t)lg;
    memcpy(cdb + 10, selecteur, 3);
}

int tunnel_lire(const uint8_t selecteur[3], uint8_t *donnees, uint32_t lg)
{
    uint8_t cdb[16];
    struct bot_resultat r;

    if (!permis_lecture_c5(selecteur, lg)) {
        fprintf(stderr, "lecture 0xC5 %02x %02x %02x de %u octets refusée : absente de la liste de permis.c\n",
                selecteur[0], selecteur[1], selecteur[2], lg);
        return -1;
    }
    cdb_tunnel(cdb, selecteur, lg);
    if (bot_commande_in(0, cdb, sizeof cdb, donnees, lg, &r) != 0)
        return -1;
    if (r.statut != 0 || r.recus != lg || r.residu != 0) {
        fprintf(stderr, "0xC5 %02x %02x %02x : statut %u, %zu octets reçus sur %u, résidu %u\n",
                selecteur[0], selecteur[1], selecteur[2], r.statut, r.recus, lg, r.residu);
        return -1;
    }
    return 0;
}

int tunnel_signature(void)
{
    static const uint8_t sel[3] = {0xFF, 0x02, 0x00};
    uint8_t d[4];
    if (tunnel_lire(sel, d, sizeof d) != 0)
        return -1;
    if (memcmp(d, "NOVA", 4) != 0) {
        fprintf(stderr, "signature inattendue : %02x %02x %02x %02x\n", d[0], d[1], d[2], d[3]);
        return -1;
    }
    return 0;
}

/* Lecture d'un sondage de 16 octets, réponse ignorée (son sens reste inconnu). */
static int sonder(uint8_t registre)
{
    const uint8_t sel[3] = {0xFF, registre, 0x00};
    uint8_t d[16];
    return tunnel_lire(sel, d, sizeof d);
}

/* Les sondages que le pilote Brother fait avant chaque échange (2a, trames 781
 * à 800 avant le dépôt de 806, puis 827 à 845, 881 à 899)… */
static int sondages_avant(void)
{
    return sonder(0x04) || sonder(0x03) || sonder(0x03) || sonder(0x05) ? -1 : 0;
}

/* …et après (trames 812 et 821, 869 et 875, 923 et 929) : ff 04 puis ff 06.
 * L'octet 8 de la réponse à ff 04 vaut 1 d'ordinaire ; après RELEASE UNIT, il
 * vaut 0 dix fois de suite, et le pilote Brother relit ff 04 toutes les 107 ms
 * environ jusqu'à ce qu'il revienne à 1 (2a, trames 120255 à 120805, pendant
 * l'éjection de la feuille), avant de passer à ff 06. On fait de même, avec
 * une limite pour ne pas boucler sans fin sur un scanner bloqué. */
#define ATTENTE_SONDAGE_MS 100
#define ATTENTE_MAX_MS 30000

static int sondages_apres(void)
{
    static const uint8_t sel[3] = {0xFF, 0x04, 0x00};
    uint8_t d[16];
    for (int attente = 0;; attente += ATTENTE_SONDAGE_MS) {
        if (tunnel_lire(sel, d, sizeof d) != 0)
            return -1;
        if (d[8] == 0x01)
            break;
        if (attente >= ATTENTE_MAX_MS) {
            fprintf(stderr, "le scanner reste occupé (ff 04) depuis %d s\n", ATTENTE_MAX_MS / 1000);
            return -1;
        }
        Sleep(ATTENTE_SONDAGE_MS);
    }
    return sonder(0x06);
}

/* Lecture d'une réponse de genre k : en-tête 02 01 k, un sondage ff 04, puis la
 * réponse 02 02 k (2a, trames 851, 857, 863 pour k = 0 ; 905, 911, 917 pour
 * k = 1). L'en-tête est lu à la même longueur que la réponse, comme le fait le
 * pilote, et son contenu n'est pas exploité. */
static int lire_reponse(uint8_t k, uint8_t *donnees, uint32_t lg)
{
    const uint8_t entete[3] = {0x02, 0x01, k}, reponse[3] = {0x02, 0x02, k};
    uint8_t tampon[64];
    if (lg > sizeof tampon)
        return -1;
    if (sondages_avant() || tunnel_lire(entete, tampon, lg) || sonder(0x04) || tunnel_lire(reponse, donnees, lg) ||
        sondages_apres())
        return -1;
    return 0;
}

/* Dépôt seul : sondages, 0xC5 sortant au sélecteur 02 03 00, sondages
 * (2a, trames 781 à 821). Le dépôt doit figurer dans la liste ci-dessus. */
int tunnel_deposer(const uint8_t *depot, uint32_t lg_depot)
{
    static const uint8_t sel_depot[3] = {0x02, 0x03, 0x00};
    uint8_t cdb[16];
    struct bot_resultat r;

    if (!permis_depot_c5(depot, lg_depot)) {
        fprintf(stderr, "dépôt 0xC5 de %u octets refusé : absent de la liste de permis.c\n", lg_depot);
        return -1;
    }
    if (sondages_avant() != 0)
        return -1;
    cdb_tunnel(cdb, sel_depot, lg_depot);
    if (bot_commande_out(0, cdb, sizeof cdb, depot, lg_depot, &r) != 0)
        return -1;
    if (r.statut != 0 || r.recus != lg_depot || r.residu != 0) {
        fprintf(stderr, "dépôt : statut %u, %zu octets envoyés sur %u, résidu %u\n", r.statut, r.recus, lg_depot,
                r.residu);
        return -1;
    }
    return sondages_apres();
}

int tunnel_statut(void)
{
    uint8_t statut[4];
    /* Statut (k = 1) : 4 octets, toujours 0 dans les captures (déduit : GOOD). */
    if (lire_reponse(1, statut, sizeof statut) != 0)
        return -1;
    if (statut[0] | statut[1] | statut[2] | statut[3]) {
        fprintf(stderr, "statut de la commande emballée : %02x %02x %02x %02x\n", statut[0], statut[1], statut[2],
                statut[3]);
        return -1;
    }
    return 0;
}

int tunnel_commande(const uint8_t *depot, uint32_t lg_depot, uint8_t *reponse, uint32_t lg_reponse)
{
    /* 1. Dépôt (2a trame 806). 2. Données de la réponse, s'il y en a (k = 0,
     * trames 851 à 863). 3. Statut (k = 1, trames 905 à 917). */
    if (tunnel_deposer(depot, lg_depot) != 0)
        return -1;
    if (lg_reponse && lire_reponse(0, reponse, lg_reponse) != 0)
        return -1;
    return tunnel_statut();
}

int tunnel_etat_bloc(struct etat_bloc *b)
{
    /* Réponse de genre 2, 24 octets (2a, trames 2418 à 2431, puis à chaque tour) :
     * six mots de 32 bits petit-boutistes, état, deux mots inconnus, deux
     * facteurs dont le produit est le volume du bloc, adresse (protocole.md §4). */
    uint8_t d[24];
    if (lire_reponse(2, d, sizeof d) != 0)
        return -1;
    uint32_t mots[6];
    for (int i = 0; i < 6; i++)
        mots[i] = (uint32_t)d[4 * i] | (uint32_t)d[4 * i + 1] << 8 | (uint32_t)d[4 * i + 2] << 16 |
                  (uint32_t)d[4 * i + 3] << 24;
    b->etat = mots[0];
    b->volume = (unsigned long long)mots[3] * mots[4];
    b->adresse = mots[5];
    return 0;
}

int tampon_lire(uint32_t adresse, uint8_t *donnees, uint32_t lg)
{
    /* CDB 0xC3 (protocole.md §1, 2a trame 52325) : c3 07, adresse et longueur
     * gros-boutistes, le reste à 0. Commande en lecture seule. */
    uint8_t cdb[16] = {0xC3, 0x07, (uint8_t)(adresse >> 24), (uint8_t)(adresse >> 16), (uint8_t)(adresse >> 8),
                       (uint8_t)adresse, (uint8_t)(lg >> 24), (uint8_t)(lg >> 16), (uint8_t)(lg >> 8), (uint8_t)lg};
    struct bot_resultat r;
    if (bot_commande_in(0, cdb, sizeof cdb, donnees, lg, &r) != 0)
        return -1;
    if (r.statut != 0 || r.recus != lg || r.residu != 0) {
        fprintf(stderr, "0xC3 à 0x%08X : statut %u, %zu octets reçus sur %u, résidu %u\n", adresse, r.statut,
                r.recus, lg, r.residu);
        return -1;
    }
    return 0;
}
