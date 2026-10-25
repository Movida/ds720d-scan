/*
 * ds720d.c : programme qui parle au scanner Brother DS-720D par WinUSB.
 *
 * Usage :
 *   ds720d descripteurs [--trace FICHIER]
 *   ds720d lun [--trace FICHIER]
 *   ds720d inquiry [--trace FICHIER]
 *   ds720d etat [--trace FICHIER]
 *
 * Chaque commande refait les précédentes, dans l'ordre où Windows énumère le
 * scanner (1b) : descripteurs, GET_MAX_LUN, puis INQUIRY ; « etat » y ajoute la
 * prise de contact du logiciel Brother par le tunnel 0xC5, en lecture seule.
 * Pourquoi enchaîner plutôt qu'isoler chaque requête : GET_MAX_LUN a besoin du
 * numéro d'interface lu dans les descripteurs, et la trace se compare alors d'un
 * bloc à la référence.
 *
 * Règle du projet : chaque requête envoyée cite sa source, section de spec et
 * trame de la capture de référence où le pilote Windows ou Brother l'envoie
 * lui-même. Rien n'est envoyé qui n'ait été observé dans 1b-enumeration.pcap,
 * sauf la Reset Recovery de bot.c, documentée par la spec Bulk-Only (BOT §5.3.4)
 * et réservée aux erreurs de transport.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "bot.h"
#include "peripherique.h"
#include "trace.h"
#include "tunnel.h"

/* Ce que l'on retient des descripteurs pour la suite. */
static struct {
    uint8_t interface;       /* bInterfaceNumber de l'interface Bulk-Only */
    uint8_t ep_in, ep_out;   /* endpoints bulk du transport Bulk-Only */
    uint16_t max_in, max_out;
    uint8_t max_lun;         /* plus haut LUN, rendu par GET_MAX_LUN */
} scanner;

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

/* Paquet SETUP d'un GET_DESCRIPTOR, USB 2.0 §9.4.3 et table 9-2 :
 *   bmRequestType 0x80 (appareil vers hôte, standard, destinataire l'appareil)
 *   bRequest      0x06 (GET_DESCRIPTOR, table 9-4)
 *   wValue        type de descripteur (table 9-5) dans l'octet haut, index dans l'octet bas
 *   wIndex        0, ou l'identifiant de langue pour un descripteur STRING
 *   wLength       nombre d'octets demandés
 * Les champs de 16 bits sont petit-boutistes (§8.1). */
static void setup_get_descripteur(uint8_t s[8], uint8_t type, uint8_t index, uint16_t langue, uint16_t lg)
{
    s[0] = 0x80;
    s[1] = 0x06;
    s[2] = index;
    s[3] = type;
    s[4] = (uint8_t)langue;
    s[5] = (uint8_t)(langue >> 8);
    s[6] = (uint8_t)lg;
    s[7] = (uint8_t)(lg >> 8);
}

/* Lit les descripteurs dans le même ordre que Windows à l'énumération (1b,
 * trames 19191 à 19206), sauf la chaîne du numéro de série, inutile ici et qui
 * ne doit pas finir dans une trace. */
static int lire_descripteurs(void)
{
    uint8_t s[8], d[256];
    long n;

    /* DEVICE, 18 octets (table 9-8) ; trame 19191, réponse trame 19194. */
    setup_get_descripteur(s, 1, 0, 0, 18);
    n = periph_controle(s, d);
    if (n != 18 || d[0] != 18 || d[1] != 1) {
        fprintf(stderr, "descripteur DEVICE inattendu (%ld octets)\n", n);
        return -1;
    }
    if (le16(d + 8) != DS720D_VID || le16(d + 10) != DS720D_PID) {
        fprintf(stderr, "ce n'est pas un DS-720D : %04X:%04X\n", le16(d + 8), le16(d + 10));
        return -1;
    }

    /* CONFIGURATION : d'abord les 9 octets de l'en-tête pour connaître wTotalLength
     * (table 9-10), puis le tout, interfaces et endpoints compris (§9.4.3).
     * Trames 19195 et 19197. */
    setup_get_descripteur(s, 2, 0, 0, 9);
    n = periph_controle(s, d);
    if (n != 9 || d[1] != 2) {
        fprintf(stderr, "en-tête CONFIGURATION inattendu (%ld octets)\n", n);
        return -1;
    }
    uint16_t total = le16(d + 2);
    if (total < 9 || total > sizeof d) {
        fprintf(stderr, "wTotalLength=%u hors des bornes prévues\n", total);
        return -1;
    }
    setup_get_descripteur(s, 2, 0, 0, total);
    n = periph_controle(s, d);
    if (n != total) {
        fprintf(stderr, "CONFIGURATION complet : %ld octets au lieu de %u\n", n, total);
        return -1;
    }

    /* Parcours : on cherche l'interface Mass Storage, SCSI transparent, Bulk-Only
     * (classe 08, sous-classe 06, protocole 50 : BOT §4.3) et ses deux endpoints
     * bulk (bmAttributes & 3 == 2, table 9-13), un dans chaque sens (bit 7 de
     * bEndpointAddress). On ne suppose pas les valeurs vues dans 1b (0x81, 0x02) :
     * on les lit. */
    int dans_bot = 0;
    /* Chaque descripteur doit tenir entier dans la réponse avant qu'on lise ses
     * champs : un bLength trompeur ne doit pas faire lire au-delà de n. */
    for (size_t i = 0; i + 2 <= (size_t)n && d[i] >= 2 && i + d[i] <= (size_t)n; i += d[i]) {
        const uint8_t *p = d + i;
        if (p[1] == 4 && p[0] >= 9) {
            dans_bot = p[5] == 0x08 && p[6] == 0x06 && p[7] == 0x50;
            if (dans_bot)
                scanner.interface = p[2];
        }
        else if (p[1] == 5 && p[0] >= 7 && dans_bot && (p[3] & 3) == 2) {
            if (p[2] & 0x80) {
                scanner.ep_in = p[2];
                scanner.max_in = le16(p + 4);
            } else {
                scanner.ep_out = p[2];
                scanner.max_out = le16(p + 4);
            }
        }
    }
    if (!scanner.ep_in || !scanner.ep_out) {
        fprintf(stderr, "pas d'interface Bulk-Only avec deux endpoints bulk\n");
        return -1;
    }

    /* STRING 0 : la liste des langues (§9.6.7). Comme Windows : 2 octets pour lire
     * bLength, puis bLength octets. Trames 19200 et 19205. */
    setup_get_descripteur(s, 3, 0, 0, 2);
    n = periph_controle(s, d);
    if (n != 2 || d[1] != 3 || d[0] < 4) {
        fprintf(stderr, "descripteur STRING 0 inattendu (%ld octets)\n", n);
        return -1;
    }
    setup_get_descripteur(s, 3, 0, 0, d[0]);
    if (periph_controle(s, d) < 4)
        return -1;

    trace_note("endpoints Bulk-Only : IN 0x%02X (%u o), OUT 0x%02X (%u o)",
               scanner.ep_in, scanner.max_in, scanner.ep_out, scanner.max_out);
    return 0;
}

/* GET_MAX_LUN, requête de classe Mass Storage Bulk-Only (BOT §3.2) :
 *   bmRequestType 0xA1 (appareil vers hôte, classe, destinataire l'interface)
 *   bRequest      0xFE (Get Max LUN)
 *   wValue        0
 *   wIndex        numéro de l'interface
 *   wLength       1 : la réponse est un seul octet, le plus haut numéro de LUN
 * Windows l'envoie trame 19223 de 1b et reçoit 0 (trame 19224) : un seul LUN.
 * BOT §3.2 permet à un appareil sans LUN multiples de répondre par un STALL ; on
 * s'arrêterait alors en le signalant, sans rien tenter d'autre. */
static int lire_max_lun(void)
{
    uint8_t s[8] = {0xA1, 0xFE, 0x00, 0x00, scanner.interface, 0x00, 0x01, 0x00};
    uint8_t lun = 0;
    if (periph_controle(s, &lun) != 1) {
        fprintf(stderr, "GET_MAX_LUN sans réponse d'un octet\n");
        return -1;
    }
    if (lun > 15) { /* BOT §3.2 : de 0 à 15 */
        fprintf(stderr, "plus haut LUN %u hors de la plage 0 à 15\n", lun);
        return -1;
    }
    scanner.max_lun = lun;
    return 0;
}

/* INQUIRY standard, première commande SCSI qu'envoie Windows (1b, trame 19225).
 * CDB de 6 octets (SPC-4, « INQUIRY command ») :
 *   octet 0     0x12, code d'opération INQUIRY
 *   octet 1     0x00, EVPD à 0 : données standard, pas une page de données vitales
 *   octet 2     0x00, code de page : doit valoir 0 quand EVPD vaut 0 (sinon
 *               CHECK CONDITION, INVALID FIELD IN CDB)
 *   octets 3-4  0x0024, longueur d'allocation en gros-boutiste : 36 octets, la
 *               taille des données standard minimales
 *   octet 5     0x00, octet de contrôle
 * Exactement le CDB de Windows en 1b. Commande en lecture seule : elle demande à
 * l'appareil de se décrire, sans rien modifier. */
static int envoyer_inquiry(void)
{
    static const uint8_t cdb[6] = {0x12, 0x00, 0x00, 0x00, 0x24, 0x00};
    uint8_t d[36];
    struct bot_resultat r;

    if (bot_commande_in(0, cdb, sizeof cdb, d, sizeof d, &r) != 0)
        return -1;
    if (r.statut != 0) {
        fprintf(stderr, "INQUIRY : statut CSW %u (échec)\n", r.statut);
        return -1;
    }
    if (r.recus != 36 || r.residu != 0) {
        fprintf(stderr, "INQUIRY : %zu octets reçus, résidu %u (36 et 0 attendus)\n", r.recus, r.residu);
        return -1;
    }
    /* Données standard (SPC-4, « Standard INQUIRY data ») : vendeur aux octets
     * 8 à 15, produit de 16 à 31, révision de 32 à 35, en ASCII complété d'espaces. */
    if (memcmp(d + 8, "Brother ", 8) != 0 || memcmp(d + 16, "DS-720D ", 8) != 0) {
        fprintf(stderr, "INQUIRY : ce n'est pas un Brother DS-720D\n");
        return -1;
    }
    trace_note("INQUIRY : %.8s / %.16s / révision %.4s", d + 8, d + 16, d + 32);
    return 0;
}

/* Prise de contact du logiciel Brother avec le scanner, rejouée telle quelle :
 * 1b, trames 20841 à 20959, juste après l'énumération par Windows. Que des
 * lectures par le tunnel 0xC5 (docs/protocole.md §2) : la signature « NOVA »
 * deux fois, des sondages d'état, puis l'identifiant fabricant et l'identifiant
 * produit, chacun précédé de son en-tête. Rien n'y modifie l'état du scanner.
 *
 * Pourquoi rejouer aussi les sondages, dont on ignore le sens : le but est
 * qu'une capture de notre passage se superpose ligne à ligne à celle du pilote
 * Brother ; en ne gardant que les lectures « utiles », on comparerait une
 * séquence que le scanner n'a jamais vue. */
static const struct {
    uint8_t selecteur[3];
    uint32_t lg;
    unsigned trame; /* trame du CBW dans 1b */
} prise_de_contact[] = {
    {{0xFF, 0x02, 0x00}, 4, 20841},  {{0xFF, 0x02, 0x00}, 4, 20848},  {{0xFF, 0x04, 0x00}, 16, 20854},
    {{0xFF, 0x03, 0x00}, 16, 20860}, {{0xFF, 0x03, 0x00}, 16, 20866}, {{0xFF, 0x05, 0x00}, 16, 20872},
    {{0x02, 0x01, 0x03}, 2, 20880},  {{0xFF, 0x04, 0x00}, 16, 20886}, {{0x02, 0x02, 0x03}, 2, 20893},
    {{0xFF, 0x04, 0x00}, 16, 20899}, {{0xFF, 0x06, 0x00}, 16, 20905}, {{0xFF, 0x04, 0x00}, 16, 20911},
    {{0xFF, 0x03, 0x00}, 16, 20917}, {{0xFF, 0x03, 0x00}, 16, 20923}, {{0xFF, 0x05, 0x00}, 16, 20929},
    {{0x02, 0x01, 0x04}, 2, 20935},  {{0xFF, 0x04, 0x00}, 16, 20941}, {{0x02, 0x02, 0x04}, 2, 20950},
    {{0xFF, 0x04, 0x00}, 16, 20956},
};

static int lire_etat(void)
{
    uint8_t d[16];
    for (size_t i = 0; i < sizeof prise_de_contact / sizeof prise_de_contact[0]; i++) {
        const uint8_t *s = prise_de_contact[i].selecteur;
        if (tunnel_lire(s, d, prise_de_contact[i].lg) != 0) {
            fprintf(stderr, "prise de contact interrompue (1b trame %u)\n", prise_de_contact[i].trame);
            return -1;
        }
        /* Contrôles des réponses dont le sens est établi (protocole.md §2). */
        if (s[0] == 0xFF && s[1] == 0x02 && memcmp(d, "NOVA", 4) != 0) {
            fprintf(stderr, "signature inattendue : %02x %02x %02x %02x\n", d[0], d[1], d[2], d[3]);
            return -1;
        }
        if (s[0] == 0x02 && s[1] == 0x02) {
            unsigned attendu = s[2] == 0x03 ? DS720D_VID : DS720D_PID;
            if ((unsigned)(d[0] << 8 | d[1]) != attendu) {
                fprintf(stderr, "identifiant 0x%02X%02X au lieu de 0x%04X\n", d[0], d[1], attendu);
                return -1;
            }
        }
    }
    trace_note("prise de contact par 0xC5 : signature NOVA, identifiants 0x%04X et 0x%04X", DS720D_VID,
               DS720D_PID);
    return 0;
}

static void usage(void)
{
    fprintf(stderr, "usage : ds720d descripteurs|lun|inquiry|etat [--trace FICHIER]\n");
}

int main(int argc, char **argv)
{
    const char *commande = NULL, *chemin_trace = NULL;
    SetConsoleOutputCP(CP_UTF8); /* la trace est en UTF-8 */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trace") == 0 && i + 1 < argc)
            chemin_trace = argv[++i];
        else if (!commande)
            commande = argv[i];
        else {
            usage();
            return 2;
        }
    }
    /* Niveau atteint par la commande : 1 descripteurs, 2 GET_MAX_LUN, 3 INQUIRY,
     * 4 prise de contact par 0xC5. */
    int niveau = 0;
    if (commande && strcmp(commande, "descripteurs") == 0)
        niveau = 1;
    else if (commande && strcmp(commande, "lun") == 0)
        niveau = 2;
    else if (commande && strcmp(commande, "inquiry") == 0)
        niveau = 3;
    else if (commande && strcmp(commande, "etat") == 0)
        niveau = 4;
    if (!niveau) {
        usage();
        return 2;
    }
    if (trace_ouvrir(chemin_trace) != 0) {
        fprintf(stderr, "impossible d'ouvrir la trace %s\n", chemin_trace);
        return 1;
    }
    int r = periph_ouvrir();
    if (r == 0)
        r = lire_descripteurs();
    if (r == 0 && niveau >= 2) {
        r = lire_max_lun();
        if (r == 0)
            trace_note("plus haut LUN : %u", scanner.max_lun);
    }
    if (r == 0 && niveau >= 3) {
        bot_init(scanner.interface, scanner.ep_in, scanner.ep_out);
        r = envoyer_inquiry();
    }
    if (r == 0 && niveau >= 4)
        r = lire_etat();
    periph_fermer();
    trace_fermer();
    return r == 0 ? 0 : 1;
}
