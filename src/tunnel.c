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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

/* Lectures permises : sélecteur et longueur, qui font tous deux partie du CDB
 * (octets 10-12 et 6-9), chacun avec une trame où le pilote Brother envoie ce
 * couple. Le dépôt (02 03 00) n'est pas ici : il passe par tunnel_commande. */
static const struct {
    uint8_t s[3];
    uint32_t lg;
    const char *source;
} permis[] = {
    {{0xFF, 0x02, 0x00}, 4, "signature, 1b trame 20841, 2a trame 772"},
    {{0xFF, 0x03, 0x00}, 16, "sondage, 1b trame 20860"},
    {{0xFF, 0x04, 0x00}, 16, "sondage, 1b trame 20854"},
    {{0xFF, 0x05, 0x00}, 16, "sondage, 1b trame 20872"},
    {{0xFF, 0x06, 0x00}, 16, "sondage, 1b trame 20905"},
    {{0x02, 0x01, 0x00}, 2, "en-tête, données, 2a trame 851"},
    {{0x02, 0x02, 0x00}, 2, "données de la réponse, 2a trame 863"},
    {{0x02, 0x01, 0x01}, 4, "en-tête, statut, 2a trame 905"},
    {{0x02, 0x02, 0x01}, 4, "statut de la commande, 2a trame 917"},
    {{0x02, 0x01, 0x02}, 24, "en-tête, bloc d'image, 2a trame 2418"},
    {{0x02, 0x02, 0x02}, 24, "état du bloc d'image, 2a trame 2431"},
    {{0x02, 0x01, 0x03}, 2, "en-tête, identifiant fabricant, 1b trame 20880"},
    {{0x02, 0x02, 0x03}, 2, "identifiant fabricant, 1b trame 20893"},
    {{0x02, 0x01, 0x04}, 2, "en-tête, identifiant produit, 1b trame 20935"},
    {{0x02, 0x02, 0x04}, 2, "identifiant produit, 1b trame 20950"},
};

/* Dépôts permis, recopiés de la capture 2a (pilote TWAIN, Button Manager
 * arrêté) et, depuis l'étape 4, de 1e-gris-300-recto-verso et 1e-gris-600-recto
 * (pilote TWAIN aussi), avec la commande SCSI-2 qu'ils emballent (protocole.md §3). */
static const struct {
    uint8_t octets[16];
    uint32_t lg;
    const char *source;
} depots_permis[] = {
    /* Opcode 0x08, absent de la table 277 des scanners : rend 2 octets, 01 00
     * avec une feuille, 00 00 sans (déduit de 2a, 1e-sans-papier, 1e-nb-300-recto). */
    {{0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00}, 10, "2a trame 808"},
    /* READ (SCSI-2 §15.2.4), type 0xA0 vendeur, qualificatif 0x0A0D, 2 octets. */
    {{0x28, 0x00, 0xa0, 0x00, 0x0a, 0x0d, 0x00, 0x00, 0x02, 0x00}, 10, "2a trame 969"},
    /* Étape 3e. Les trois SEND vendeur, dont l'effet exact reste inconnu, ont
     * l'accord écrit de David du 25/10/2026 (CLAUDE.md) : le pilote TWAIN les
     * envoie avec ces octets avant chaque scan, dans toutes les captures. */
    /* SEND (SCSI-2 §15.2.6), type 0x95 vendeur, qualificatif 0x0001, 2 octets à 0. */
    {{0x2a, 0x00, 0x95, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, 12, "2a trame 1755"},
    /* SEND, type 0x96 vendeur, qualificatif 0x0001, 2 octets à 0. */
    {{0x2a, 0x00, 0x96, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, 12, "2a trame 1859"},
    /* RESERVE UNIT (SCSI-2 §10.2.10), CDB de 6 octets complété de zéros. */
    {{0x16}, 10, "2a trame 2179"},
    /* SCAN (SCSI-2 §15.2.5), liste de fenêtres vide, contrôle 0x80 (bit vendeur). */
    {{0x1b, 0x00, 0x00, 0x00, 0x00, 0x80}, 10, "2a trame 2278"},
    /* READ (SCSI-2 §15.2.4), type 0x00 image, qualificatif 0x0A0D, 0x1FEAE0 octets
     * (2a ; le même à 600 dpi, 1e-gris-600-recto trame 3033). */
    {{0x28, 0x00, 0x00, 0x00, 0x0a, 0x0d, 0x1f, 0xea, 0xe0, 0x00}, 10, "2a trame 2375"},
    /* Étape 4e. Le même READ en recto-verso, pour 0x1E6000 octets (sens de la
     * longueur inconnu, comme en 2a ; les blocs restent de 622 080 o). */
    {{0x28, 0x00, 0x00, 0x00, 0x0a, 0x0d, 0x1e, 0x60, 0x00, 0x00}, 10, "1e-gris-300-recto-verso trame 2811"},
    /* RELEASE UNIT (SCSI-2 §10.2.9). */
    {{0x17}, 10, "2a trame 120250"},
};

/* Les deux dépôts de plus de 16 octets, à part pour garder le tableau compact. */
static const uint8_t send_83[28] = {
    /* SEND, type 0x83 vendeur, 18 octets (2a trame 1961) : neuf mots de 16 bits
     * gros-boutistes, 0x0400 aux positions 0, 4 et 8 et 0 ailleurs, soit une
     * matrice 3 × 3 diagonale (déduit : matrice de couleur identité, 0x0400 = 1). */
    0x2a, 0x00, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
};
static const uint8_t set_window[89] = {
    /* SET WINDOW (SCSI-2 §15.2.7), 79 octets de paramètres (2a trame 2067) : en-tête
     * de 8 octets, puis la fenêtre 0 en 300 × 300 ppp, 10 368 × 16 800 unités de
     * 1/1200 po, RVB multiniveau 8 bits, et 31 octets vendeur (protocole.md §3). */
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x00,             /* CDB */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47,                         /* en-tête */
    0x00, 0x00, 0x01, 0x2c, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* id, auto, résolutions, X */
    0x00, 0x00, 0x00, 0x00, 0x28, 0x80, 0x00, 0x00, 0x41, 0xa0,             /* Y, largeur, longueur */
    0x80, 0x80, 0x80, 0x05, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, /* luminosité … compression */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                     /* réservés */
    0xff, 0x1d, 0xe0, 0xff, 0x00, 0x1e, 0x60, 0x10, 0x68, 0x10, 0x00, 0x00, /* octets vendeur */
    0x64, 0x00, 0x64, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
/* Étape 4e. SET WINDOW du recto-verso (1e-gris-300-recto-verso trame 2500), la
 * fenêtre de 2a à cinq octets près (protocole.md §3 et §6) : longueur 17 340
 * unités au lieu de 16 800 (octets 38-39, 14,45 po : le verso, vu 0,45 po plus
 * tard, couvre encore 14 po), octets vendeur 7-8 à 0x21E0 au lieu de 0x1068
 * (8 672 = deux faces de 4 336 lignes, déduit) et octet vendeur 17 à 0x10, le
 * bit qui demande le recto-verso (déduit, et confirmé par l'alternance des
 * blocs recto et verso qui suit dans la capture). */
static const uint8_t set_window_rv[89] = {
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x00,             /* CDB */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47,                         /* en-tête */
    0x00, 0x00, 0x01, 0x2c, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* id, auto, résolutions, X */
    0x00, 0x00, 0x00, 0x00, 0x28, 0x80, 0x00, 0x00, 0x43, 0xbc,             /* Y, largeur, longueur */
    0x80, 0x80, 0x80, 0x05, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, /* luminosité … compression */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                     /* réservés */
    0xff, 0x1d, 0xe0, 0xff, 0x00, 0x1e, 0x60, 0x21, 0xe0, 0x10, 0x00, 0x00, /* octets vendeur */
    0x64, 0x00, 0x64, 0x00, 0x64, 0x10, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
/* Étape 4f. SET WINDOW à 600 dpi (1e-gris-600-recto trame 2718), la fenêtre de
 * 2a à quatre octets près : résolution Y 600 (octets 22-23 ; X reste à 300) et
 * octets vendeur 7-8 à 0x20D0 (8 400 lignes de 14 po à 600 ppp, déduit). */
static const uint8_t set_window_600[89] = {
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x00,             /* CDB */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47,                         /* en-tête */
    0x00, 0x00, 0x01, 0x2c, 0x02, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* id, auto, résolutions, X */
    0x00, 0x00, 0x00, 0x00, 0x28, 0x80, 0x00, 0x00, 0x41, 0xa0,             /* Y, largeur, longueur */
    0x80, 0x80, 0x80, 0x05, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, /* luminosité … compression */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,                                     /* réservés */
    0xff, 0x1d, 0xe0, 0xff, 0x00, 0x1e, 0x60, 0x20, 0xd0, 0x10, 0x00, 0x00, /* octets vendeur */
    0x64, 0x00, 0x64, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* Les dépôts de plus de 16 octets, chacun avec sa trame. */
static const struct {
    const uint8_t *octets;
    uint32_t lg;
    const char *source;
} depots_longs[] = {
    {send_83, sizeof send_83, "2a trame 1961"},
    {set_window, sizeof set_window, "2a trame 2067"},
    {set_window_rv, sizeof set_window_rv, "1e-gris-300-recto-verso trame 2500"},
    {set_window_600, sizeof set_window_600, "1e-gris-600-recto trame 2718"},
};

static int lecture_permise(const uint8_t s[3], uint32_t lg)
{
    for (size_t i = 0; i < sizeof permis / sizeof permis[0]; i++)
        if (memcmp(permis[i].s, s, 3) == 0 && permis[i].lg == lg)
            return 1;
    return 0;
}

static int depot_permis(const uint8_t *depot, uint32_t lg)
{
    for (size_t i = 0; i < sizeof depots_longs / sizeof depots_longs[0]; i++)
        if (depots_longs[i].lg == lg && memcmp(depots_longs[i].octets, depot, lg) == 0)
            return 1;
    for (size_t i = 0; i < sizeof depots_permis / sizeof depots_permis[0]; i++)
        if (depots_permis[i].lg == lg && memcmp(depots_permis[i].octets, depot, lg) == 0)
            return 1;
    return 0;
}

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

    if (!lecture_permise(selecteur, lg)) {
        fprintf(stderr, "lecture 0xC5 %02x %02x %02x de %u octets refusée : absente de la liste de tunnel.c\n",
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

    if (!depot_permis(depot, lg_depot)) {
        fprintf(stderr, "dépôt 0xC5 de %u octets refusé : absent de la liste de tunnel.c\n", lg_depot);
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
