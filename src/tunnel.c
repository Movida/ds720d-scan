/*
 * tunnel.c : lectures par la commande vendeur 0xC5 (docs/protocole.md §2).
 *
 * Forme du CDB, identique dans les 17 captures de référence (protocole.md §1) :
 *   octet 0      0xC5, code d'opération du groupe 6, réservé aux fabricants
 *                (SCSI-2 §7.2.1)
 *   octet 1      0x07, constant, sens inconnu
 *   octets 2-5   0 (l'adresse ne sert qu'à 0xC3)
 *   octets 6-9   longueur des données, gros-boutiste, égale à celle du CBW
 *   octets 10-12 sélecteur
 *   octets 13-15 0
 */
#include "tunnel.h"

#include <stdio.h>
#include <string.h>

/* Sélecteurs de lecture permis, chacun avec une trame où le pilote Brother
 * l'envoie. Seuls ceux-là partent ; un sélecteur de dépôt (02 03 00) n'est pas
 * ici, puisqu'il écrit : il viendra à l'étape 3d, avec son propre contrôle. */
static const struct {
    uint8_t s[3];
    const char *source;
} permis[] = {
    {{0xFF, 0x02, 0x00}, "signature, 1b trame 20841, 2a trame 772"},
    {{0xFF, 0x03, 0x00}, "sondage, 1b trame 20860"},
    {{0xFF, 0x04, 0x00}, "sondage, 1b trame 20854"},
    {{0xFF, 0x05, 0x00}, "sondage, 1b trame 20872"},
    {{0xFF, 0x06, 0x00}, "sondage, 1b trame 20905"},
    {{0x02, 0x01, 0x03}, "en-tête, identifiant fabricant, 1b trame 20880"},
    {{0x02, 0x02, 0x03}, "identifiant fabricant, 1b trame 20893"},
    {{0x02, 0x01, 0x04}, "en-tête, identifiant produit, 1b trame 20935"},
    {{0x02, 0x02, 0x04}, "identifiant produit, 1b trame 20950"},
};

static int selecteur_permis(const uint8_t s[3])
{
    for (size_t i = 0; i < sizeof permis / sizeof permis[0]; i++)
        if (memcmp(permis[i].s, s, 3) == 0)
            return 1;
    return 0;
}

int tunnel_lire(const uint8_t selecteur[3], uint8_t *donnees, uint32_t lg)
{
    uint8_t cdb[16] = {0};
    struct bot_resultat r;

    if (!selecteur_permis(selecteur)) {
        fprintf(stderr, "sélecteur 0xC5 %02x %02x %02x refusé : absent de la liste de tunnel.c\n",
                selecteur[0], selecteur[1], selecteur[2]);
        return -1;
    }
    cdb[0] = 0xC5;
    cdb[1] = 0x07;
    cdb[6] = (uint8_t)(lg >> 24); /* longueur, gros-boutiste */
    cdb[7] = (uint8_t)(lg >> 16);
    cdb[8] = (uint8_t)(lg >> 8);
    cdb[9] = (uint8_t)lg;
    memcpy(cdb + 10, selecteur, 3);

    if (bot_commande_in(0, cdb, sizeof cdb, donnees, lg, &r) != 0)
        return -1;
    if (r.statut != 0 || r.recus != lg || r.residu != 0) {
        fprintf(stderr, "0xC5 %02x %02x %02x : statut %u, %zu octets reçus sur %u, résidu %u\n",
                selecteur[0], selecteur[1], selecteur[2], r.statut, r.recus, lg, r.residu);
        return -1;
    }
    return 0;
}
