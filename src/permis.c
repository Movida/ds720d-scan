/*
 * permis.c : la barrière des commandes observées. Voir permis.h.
 *
 * Les tables de lectures et de dépôts 0xC5 viennent de tunnel.c (étapes 3 et
 * 4), déplacées ici à l'étape 6e sans changer un octet, pour que le pilote noyau
 * applique la même liste que l'outil.
 */
#include "permis.h"

#include <string.h>

/* Paquets SETUP permis : ceux que Windows envoie au scanner dans 1b, que notre
 * programme rejoue depuis l'étape 2 (lire_descripteurs, lire_max_lun de
 * src/ds720d.c). Tous en lecture (bit 7 de bmRequestType à 1). */
static const struct {
    unsigned char setup[8];
    const char *source;
} controles_permis[] = {
    {{0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00}, "DEVICE, 18 octets, 1b trame 19191"},
    {{0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x09, 0x00}, "CONFIGURATION, en-tete, 1b trame 19195"},
    {{0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x20, 0x00}, "CONFIGURATION complet, 32 octets, 1b trame 19197"},
    {{0x80, 0x06, 0x00, 0x03, 0x00, 0x00, 0x02, 0x00}, "STRING 0, bLength, 1b trame 19200"},
    {{0x80, 0x06, 0x00, 0x03, 0x00, 0x00, 0x04, 0x00}, "STRING 0, langues, 1b trame 19205"},
    {{0xA1, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}, "GET_MAX_LUN, BOT 3.2, 1b trame 19223"},
};

/* Lectures permises : sélecteur et longueur, qui font tous deux partie du CDB
 * (octets 10-12 et 6-9), chacun avec une trame où le pilote Brother envoie ce
 * couple. Le dépôt (02 03 00) n'est pas ici : il passe par permis_depot_c5. */
static const struct {
    unsigned char s[3];
    unsigned int lg;
    const char *source;
} lectures_permises[] = {
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
    unsigned char octets[16];
    unsigned int lg;
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

/* Les dépôts de plus de 16 octets, à part pour garder le tableau compact. */
static const unsigned char send_83[28] = {
    /* SEND, type 0x83 vendeur, 18 octets (2a trame 1961) : neuf mots de 16 bits
     * gros-boutistes, 0x0400 aux positions 0, 4 et 8 et 0 ailleurs, soit une
     * matrice 3 × 3 diagonale (déduit : matrice de couleur identité, 0x0400 = 1). */
    0x2a, 0x00, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00, 0x04, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
};
static const unsigned char set_window[89] = {
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
/* Étape 4e, accord écrit de David du 25/10/2026 pour ce dépôt, le READ du
 * recto-verso et la fenêtre du 600 dpi ci-dessous (CLAUDE.md).
 * SET WINDOW du recto-verso (1e-gris-300-recto-verso trame 2500), la
 * fenêtre de 2a à cinq octets près (protocole.md §3 et §6) : longueur 17 340
 * unités au lieu de 16 800 (octets 38-39, 14,45 po : le verso, vu 0,45 po plus
 * tard, couvre encore 14 po), octets vendeur 7-8 à 0x21E0 au lieu de 0x1068
 * (8 672, le double de 4 336, à une ligne près les 4 335 lignes de 14,45 po :
 * le nombre de lignes des deux faces, déduit) et octet vendeur 17 à 0x10, le
 * bit qui demande le recto-verso (déduit, et confirmé par l'alternance des
 * blocs recto et verso qui suit dans la capture). */
static const unsigned char set_window_rv[89] = {
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
static const unsigned char set_window_600[89] = {
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
    const unsigned char *octets;
    unsigned int lg;
    const char *source;
} depots_longs[] = {
    {send_83, sizeof send_83, "2a trame 1961"},
    {set_window, sizeof set_window, "2a trame 2067"},
    {set_window_rv, sizeof set_window_rv, "1e-gris-300-recto-verso trame 2500"},
    {set_window_600, sizeof set_window_600, "1e-gris-600-recto trame 2718"},
};

/* INQUIRY standard de Windows (1b trame 19225), le seul que l'on envoie :
 * EVPD à 0, page 0, 36 octets d'allocation (src/ds720d.c, envoyer_inquiry). */
static const unsigned char cdb_inquiry[6] = {0x12, 0x00, 0x00, 0x00, 0x24, 0x00};
#define LG_INQUIRY 36u

/* Plus grande lecture 0xC3 : 65 536 octets, celle du pilote Brother (2a trame
 * 52325) ; la dernière lecture d'un bloc est plus courte (32 256 o dans 2a). */
#define LG_C3_MAX 65536u

#define NB(t) (sizeof(t) / sizeof((t)[0]))

int permis_controle(const unsigned char setup[8])
{
    for (unsigned int i = 0; i < NB(controles_permis); i++)
        if (memcmp(controles_permis[i].setup, setup, 8) == 0)
            return 1;
    return 0;
}

int permis_lecture_c5(const unsigned char selecteur[3], unsigned int lg)
{
    for (unsigned int i = 0; i < NB(lectures_permises); i++)
        if (memcmp(lectures_permises[i].s, selecteur, 3) == 0 && lectures_permises[i].lg == lg)
            return 1;
    return 0;
}

int permis_depot_c5(const unsigned char *depot, unsigned int lg)
{
    if (!depot)
        return 0;
    for (unsigned int i = 0; i < NB(depots_longs); i++)
        if (depots_longs[i].lg == lg && memcmp(depots_longs[i].octets, depot, lg) == 0)
            return 1;
    for (unsigned int i = 0; i < NB(depots_permis); i++)
        if (depots_permis[i].lg == lg && memcmp(depots_permis[i].octets, depot, lg) == 0)
            return 1;
    return 0;
}

static unsigned int be32(const unsigned char *p)
{
    return (unsigned int)p[0] << 24 | (unsigned int)p[1] << 16 | (unsigned int)p[2] << 8 | p[3];
}

/* Octets tous nuls de p[debut] à p[fin - 1]. */
static int nuls(const unsigned char *p, unsigned int debut, unsigned int fin)
{
    for (unsigned int i = debut; i < fin; i++)
        if (p[i])
            return 0;
    return 1;
}

int permis_bot(const unsigned char *cdb, unsigned int lg_cdb, int sortant, unsigned int lg,
               const unsigned char *donnees_sortantes)
{
    if (!cdb || lg_cdb < 1 || lg_cdb > 16)
        return 0;
    switch (cdb[0]) {
    case 0x12:
        /* INQUIRY : exactement le CDB de 1b, en lecture de 36 octets. */
        return lg_cdb == sizeof cdb_inquiry && memcmp(cdb, cdb_inquiry, sizeof cdb_inquiry) == 0 && !sortant &&
               lg == LG_INQUIRY;
    case 0xC5:
        /* Forme du CDB, identique dans les 17 captures de référence
         * (protocole.md §1) : c5 07, adresse nulle, longueur gros-boutiste
         * égale à celle du CBW, sélecteur, trois octets nuls. */
        if (lg_cdb != 16 || cdb[1] != 0x07 || !nuls(cdb, 2, 6) || be32(cdb + 6) != lg || !nuls(cdb, 13, 16))
            return 0;
        if (cdb[10] == 0x02 && cdb[11] == 0x03 && cdb[12] == 0x00)
            return sortant && permis_depot_c5(donnees_sortantes, lg);
        return !sortant && permis_lecture_c5(cdb + 10, lg);
    case 0xC3:
        /* c3 07, adresse quelconque (celle qu'annonce le scanner), longueur
         * gros-boutiste égale à celle du CBW, six octets nuls ; lecture seule
         * de la mémoire d'image du scanner (protocole.md §1 et §4). */
        return lg_cdb == 16 && cdb[1] == 0x07 && be32(cdb + 6) == lg && nuls(cdb, 10, 16) && !sortant && lg >= 1 &&
               lg <= LG_C3_MAX;
    default:
        return 0;
    }
}
