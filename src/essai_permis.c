/*
 * essai_permis.c : banc d'essai de la barrière (permis.c), sans scanner.
 *
 * Ce que le pilote noyau acceptera ou refusera (étape 6e) se vérifie ici, hors
 * ligne, avant tout chargement : chaque requête observée doit passer, et chaque
 * variante (un octet changé, une longueur, un sens, un opcode jamais envoyé)
 * doit être refusée. Rien ne part vers un appareil : ce programme n'appelle que
 * permis.c.
 * Code de sortie : 0 si tous les cas se comportent comme prévu.
 */
#include <stdio.h>
#include <string.h>

#include "permis.h"

static int echecs, cas;

static void attendu(int obtenu, int voulu, const char *quoi)
{
    cas++;
    if (!obtenu != !voulu) {
        echecs++;
        printf("ECHEC : %s %s alors qu'il devait être %s\n", quoi, obtenu ? "permis" : "refusé",
               voulu ? "permis" : "refusé");
    }
}

/* CDB 0xC5 de la forme observée (protocole.md §1). */
static void cdb_c5(unsigned char cdb[16], unsigned char s0, unsigned char s1, unsigned char s2, unsigned int lg)
{
    memset(cdb, 0, 16);
    cdb[0] = 0xC5;
    cdb[1] = 0x07;
    cdb[6] = (unsigned char)(lg >> 24);
    cdb[7] = (unsigned char)(lg >> 16);
    cdb[8] = (unsigned char)(lg >> 8);
    cdb[9] = (unsigned char)lg;
    cdb[10] = s0;
    cdb[11] = s1;
    cdb[12] = s2;
}

/* CDB 0xC3 de la forme observée (2a trame 52325). */
static void cdb_c3(unsigned char cdb[16], unsigned int adresse, unsigned int lg)
{
    memset(cdb, 0, 16);
    cdb[0] = 0xC3;
    cdb[1] = 0x07;
    cdb[2] = (unsigned char)(adresse >> 24);
    cdb[3] = (unsigned char)(adresse >> 16);
    cdb[4] = (unsigned char)(adresse >> 8);
    cdb[5] = (unsigned char)adresse;
    cdb[6] = (unsigned char)(lg >> 24);
    cdb[7] = (unsigned char)(lg >> 16);
    cdb[8] = (unsigned char)(lg >> 8);
    cdb[9] = (unsigned char)lg;
}

int main(void)
{
    unsigned char cdb[16];

    /* 1. Transferts de contrôle : les six paquets de 1b, et rien d'autre. */
    static const unsigned char setups_permis[6][8] = {
        {0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00}, {0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x09, 0x00},
        {0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x20, 0x00}, {0x80, 0x06, 0x00, 0x03, 0x00, 0x00, 0x02, 0x00},
        {0x80, 0x06, 0x00, 0x03, 0x00, 0x00, 0x04, 0x00}, {0xA1, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
    };
    for (int i = 0; i < 6; i++)
        attendu(permis_controle(setups_permis[i]), 1, "SETUP observé");
    static const unsigned char setups_refuses[][8] = {
        {0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, /* SET_CONFIGURATION : réservé au pilote */
        {0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* SET_CONFIGURATION 0, jamais observé */
        {0x80, 0x06, 0x03, 0x03, 0x09, 0x04, 0x02, 0x00}, /* STRING 3 : le numéro de série */
        {0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0xff, 0x00}, /* CONFIGURATION, wLength jamais demandé par nous */
        {0x21, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* Bulk-Only Reset : réservé au pilote */
        {0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* requête vendeur quelconque */
        {0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, /* CLEAR_FEATURE */
    };
    for (size_t i = 0; i < sizeof setups_refuses / sizeof setups_refuses[0]; i++)
        attendu(permis_controle(setups_refuses[i]), 0, "SETUP non observé");

    /* 2. INQUIRY : le CDB de 1b seulement. */
    static const unsigned char inquiry[6] = {0x12, 0x00, 0x00, 0x00, 0x24, 0x00};
    static const unsigned char inquiry_vpd[6] = {0x12, 0x01, 0x80, 0x00, 0x24, 0x00};
    attendu(permis_bot(inquiry, 6, 0, 36, NULL), 1, "INQUIRY de 1b");
    attendu(permis_bot(inquiry, 6, 0, 255, NULL), 0, "INQUIRY de 255 octets");
    attendu(permis_bot(inquiry, 6, 1, 36, inquiry), 0, "INQUIRY sortant");
    attendu(permis_bot(inquiry_vpd, 6, 0, 36, NULL), 0, "INQUIRY de page VPD (numéro de série)");

    /* 3. Opcodes jamais envoyés par notre code, dont ceux qui écrivent. */
    static const unsigned char tur[6] = {0x00, 0, 0, 0, 0, 0};
    static const unsigned char ecrire10[10] = {0x2A, 0, 0, 0, 0, 0, 0, 0, 1, 0};
    static const unsigned char lire10[10] = {0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0};
    static const unsigned char formater[6] = {0x04, 0, 0, 0, 0, 0};
    static const unsigned char mode_select[6] = {0x15, 0x10, 0, 0, 0x0C, 0};
    static const unsigned char write_buffer[10] = {0x3B, 0x05, 0, 0, 0, 0, 0, 0x10, 0, 0};
    unsigned char zero512[512] = {0};
    attendu(permis_bot(tur, 6, 0, 0, NULL), 0, "TEST UNIT READY (vu chez Windows en 5d, jamais chez nous)");
    attendu(permis_bot(ecrire10, 10, 1, 512, zero512), 0, "WRITE(10)");
    attendu(permis_bot(lire10, 10, 0, 512, NULL), 0, "READ(10) du faux disque");
    attendu(permis_bot(formater, 6, 0, 0, NULL), 0, "FORMAT UNIT");
    attendu(permis_bot(mode_select, 6, 1, 12, zero512), 0, "MODE SELECT");
    attendu(permis_bot(write_buffer, 10, 1, 4096, zero512), 0, "WRITE BUFFER (firmware)");

    /* 4. Lectures 0xC5 : chaque couple sélecteur-longueur observé, puis des variantes. */
    static const struct {
        unsigned char s[3];
        unsigned int lg;
    } lectures[] = {
        {{0xFF, 0x02, 0x00}, 4},  {{0xFF, 0x03, 0x00}, 16}, {{0xFF, 0x04, 0x00}, 16}, {{0xFF, 0x05, 0x00}, 16},
        {{0xFF, 0x06, 0x00}, 16}, {{0x02, 0x01, 0x00}, 2},  {{0x02, 0x02, 0x00}, 2},  {{0x02, 0x01, 0x01}, 4},
        {{0x02, 0x02, 0x01}, 4},  {{0x02, 0x01, 0x02}, 24}, {{0x02, 0x02, 0x02}, 24}, {{0x02, 0x01, 0x03}, 2},
        {{0x02, 0x02, 0x03}, 2},  {{0x02, 0x01, 0x04}, 2},  {{0x02, 0x02, 0x04}, 2},
    };
    for (size_t i = 0; i < sizeof lectures / sizeof lectures[0]; i++) {
        cdb_c5(cdb, lectures[i].s[0], lectures[i].s[1], lectures[i].s[2], lectures[i].lg);
        attendu(permis_bot(cdb, 16, 0, lectures[i].lg, NULL), 1, "lecture 0xC5 observée");
        attendu(permis_bot(cdb, 16, 0, lectures[i].lg + 1, NULL), 0, "lecture 0xC5, CBW plus long que le CDB");
        attendu(permis_bot(cdb, 16, 1, lectures[i].lg, zero512), 0, "lecture 0xC5 déclarée sortante");
    }
    cdb_c5(cdb, 0xFF, 0x07, 0x00, 16);
    attendu(permis_bot(cdb, 16, 0, 16, NULL), 0, "sélecteur ff 07 00, jamais observé");
    cdb_c5(cdb, 0xFF, 0x04, 0x00, 17);
    attendu(permis_bot(cdb, 16, 0, 17, NULL), 0, "sondage ff 04 de 17 octets");
    cdb_c5(cdb, 0x02, 0x02, 0x05, 2);
    attendu(permis_bot(cdb, 16, 0, 2, NULL), 0, "réponse 02 02 05, jamais observée");
    cdb_c5(cdb, 0xFF, 0x04, 0x00, 16);
    cdb[1] = 0x08;
    attendu(permis_bot(cdb, 16, 0, 16, NULL), 0, "0xC5 dont l'octet 1 n'est pas 07");
    cdb_c5(cdb, 0xFF, 0x04, 0x00, 16);
    cdb[3] = 0x01;
    attendu(permis_bot(cdb, 16, 0, 16, NULL), 0, "0xC5 avec une adresse non nulle");
    cdb_c5(cdb, 0xFF, 0x04, 0x00, 16);
    cdb[15] = 0x01;
    attendu(permis_bot(cdb, 16, 0, 16, NULL), 0, "0xC5 avec un octet final non nul");
    cdb_c5(cdb, 0xFF, 0x04, 0x00, 16);
    attendu(permis_bot(cdb, 12, 0, 16, NULL), 0, "0xC5 en CDB de 12 octets");

    /* 5. Dépôts 0xC5 : chaque dépôt observé, puis un octet changé. Depuis 6i
     * (relecture de fond), tous ceux du scan, recopiés de src/ds720d.c (les
     * octets que l'outil dépose), et non de permis.c : l'essai vérifie ainsi
     * que les deux listes concordent. */
    static const unsigned char papier[10] = {0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const unsigned char lire_a0[10] = {0x28, 0x00, 0xa0, 0x00, 0x0a, 0x0d, 0x00, 0x00, 0x02, 0x00};
    static const unsigned char reserve[10] = {0x16};
    static const unsigned char scan[10] = {0x1b, 0x00, 0x00, 0x00, 0x00, 0x80};
    static const unsigned char lire_image[10] = {0x28, 0x00, 0x00, 0x00, 0x0a, 0x0d, 0x1f, 0xea, 0xe0, 0x00};
    static const unsigned char release[10] = {0x17};
    static const unsigned char send_83[28] = {0x2a, 0x00, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00,
                                              0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
                                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00};
    static const unsigned char send_95[12] = {0x2a, 0x00, 0x95, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
    static const unsigned char send_96[12] = {0x2a, 0x00, 0x96, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
    static const unsigned char lire_image_rv[10] = {0x28, 0x00, 0x00, 0x00, 0x0a, 0x0d, 0x1e, 0x60, 0x00, 0x00};
    static const unsigned char fenetre[89] = {
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47,
        0x00, 0x00, 0x01, 0x2c, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x80,
        0x00, 0x00, 0x41, 0xa0, 0x80, 0x80, 0x80, 0x05, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0x1d, 0xe0, 0xff, 0x00, 0x1e, 0x60, 0x10, 0x68, 0x10, 0x00, 0x00, 0x64, 0x00,
        0x64, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const unsigned char fenetre_rv[89] = {
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47,
        0x00, 0x00, 0x01, 0x2c, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x80,
        0x00, 0x00, 0x43, 0xbc, 0x80, 0x80, 0x80, 0x05, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0x1d, 0xe0, 0xff, 0x00, 0x1e, 0x60, 0x21, 0xe0, 0x10, 0x00, 0x00, 0x64, 0x00,
        0x64, 0x00, 0x64, 0x10, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const unsigned char fenetre_600[89] = {
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47,
        0x00, 0x00, 0x01, 0x2c, 0x02, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x80,
        0x00, 0x00, 0x41, 0xa0, 0x80, 0x80, 0x80, 0x05, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0x1d, 0xe0, 0xff, 0x00, 0x1e, 0x60, 0x20, 0xd0, 0x10, 0x00, 0x00, 0x64, 0x00,
        0x64, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const struct {
        const unsigned char *d;
        unsigned int lg;
    } depots[] = {{papier, 10},     {lire_a0, 10},     {send_95, 12},        {send_96, 12},   {send_83, 28},
                  {fenetre, 89},    {fenetre_rv, 89},  {fenetre_600, 89},    {reserve, 10},   {scan, 10},
                  {lire_image, 10}, {lire_image_rv, 10}, {release, 10}};
    for (size_t i = 0; i < sizeof depots / sizeof depots[0]; i++) {
        unsigned char copie[89];
        cdb_c5(cdb, 0x02, 0x03, 0x00, depots[i].lg);
        attendu(permis_bot(cdb, 16, 1, depots[i].lg, depots[i].d), 1, "dépôt observé");
        attendu(permis_bot(cdb, 16, 0, depots[i].lg, depots[i].d), 0, "dépôt déclaré entrant");
        memcpy(copie, depots[i].d, depots[i].lg);
        copie[depots[i].lg - 1] ^= 0x01;
        attendu(permis_bot(cdb, 16, 1, depots[i].lg, copie), 0, "dépôt au dernier octet changé");
        /* Bit 6 de l'opcode, et non le bit 0 : RESERVE UNIT (0x16) et RELEASE
         * UNIT (0x17) ne diffèrent que par lui, et sont permis tous les deux. */
        memcpy(copie, depots[i].d, depots[i].lg);
        copie[0] ^= 0x40;
        attendu(permis_bot(cdb, 16, 1, depots[i].lg, copie), 0, "dépôt à l'opcode changé");
    }
    /* Fenêtres jamais observées, à un réglage près d'une fenêtre permise :
     * 600 × 600 ppp (octets 20-21, résolution X), et recto-verso à 600 ppp. */
    unsigned char fenetre_essai[89];
    cdb_c5(cdb, 0x02, 0x03, 0x00, 89);
    memcpy(fenetre_essai, fenetre_600, 89);
    fenetre_essai[20] = 0x02;
    fenetre_essai[21] = 0x58;
    attendu(permis_bot(cdb, 16, 1, 89, fenetre_essai), 0, "SET WINDOW 600 × 600 ppp");
    memcpy(fenetre_essai, fenetre_rv, 89);
    fenetre_essai[22] = 0x02;
    fenetre_essai[23] = 0x58;
    attendu(permis_bot(cdb, 16, 1, 89, fenetre_essai), 0, "SET WINDOW recto-verso à 600 ppp");
    cdb_c5(cdb, 0x02, 0x03, 0x00, 10);
    attendu(permis_bot(cdb, 16, 1, 10, NULL), 0, "dépôt sans données");
    cdb_c5(cdb, 0x02, 0x03, 0x00, 11);
    attendu(permis_bot(cdb, 16, 1, 11, papier), 0, "dépôt de 11 octets");

    /* 6. Lectures 0xC3 : 64 Kio et la dernière lecture de 2a, puis des variantes. */
    cdb_c3(cdb, 0x0059AA00, 65536);
    attendu(permis_bot(cdb, 16, 0, 65536, NULL), 1, "0xC3 de 64 Kio (2a trame 52325)");
    cdb_c3(cdb, 0x0059AA00 + 9 * 65536, 32256);
    attendu(permis_bot(cdb, 16, 0, 32256, NULL), 1, "0xC3 de 32 256 octets (fin de bloc de 2a)");
    cdb_c3(cdb, 0, 65537);
    attendu(permis_bot(cdb, 16, 0, 65537, NULL), 0, "0xC3 de plus de 64 Kio");
    cdb_c3(cdb, 0, 0);
    attendu(permis_bot(cdb, 16, 0, 0, NULL), 0, "0xC3 de 0 octet");
    cdb_c3(cdb, 0, 512);
    attendu(permis_bot(cdb, 16, 1, 512, zero512), 0, "0xC3 sortant");
    attendu(permis_bot(cdb, 16, 0, 1024, NULL), 0, "0xC3, CBW plus long que le CDB");
    cdb[12] = 0x01;
    attendu(permis_bot(cdb, 16, 0, 512, NULL), 0, "0xC3 avec un octet final non nul");

    /* 7. CDB absent ou de longueur impossible (BOT §5.1 : 1 à 16 octets). */
    attendu(permis_bot(NULL, 6, 0, 36, NULL), 0, "CDB absent");
    attendu(permis_bot(inquiry, 0, 0, 36, NULL), 0, "CDB de 0 octet");
    attendu(permis_bot(inquiry, 17, 0, 36, NULL), 0, "CDB de 17 octets");

    printf("%d cas, %d échec(s)\n", cas, echecs);
    return echecs ? 1 : 0;
}
