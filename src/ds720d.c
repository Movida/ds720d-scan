/*
 * ds720d.c : programme qui parle au scanner Brother DS-720D par WinUSB.
 *
 * Usage :
 *   ds720d descripteurs [--trace FICHIER]
 *   ds720d lun [--trace FICHIER]
 *   ds720d inquiry [--trace FICHIER]
 *   ds720d etat [--trace FICHIER]
 *   ds720d papier [--trace FICHIER]
 *   ds720d scan --sortie FICHIER.brut [--recto-verso | --ppp 600] [--feuilles N] [--trace FICHIER]
 *
 * Chaque commande refait les précédentes, dans l'ordre où Windows énumère le
 * scanner (1b) : descripteurs, GET_MAX_LUN, puis INQUIRY ; « etat » y ajoute la
 * prise de contact du logiciel Brother par le tunnel 0xC5, en lecture seule ;
 * « papier » y ajoute les questions que pose le pilote TWAIN avant un scan
 * (présence du papier), par des commandes de lecture déposées dans le tunnel ;
 * « scan » rejoue ensuite le scan d'une page de 2a et écrit l'image brute
 * (docs/protocole.md §5) dans FICHIER.brut, hors du dépôt. Depuis l'étape 4,
 * --recto-verso rejoue 1e-gris-300-recto-verso (une face par fichier,
 * FICHIER-recto.brut et FICHIER-verso.brut) et --ppp 600 rejoue
 * 1e-gris-600-recto ; --feuilles N attend et scanne N feuilles d'affilée
 * (FICHIER-p1….brut).
 * Pourquoi enchaîner plutôt qu'isoler chaque requête : GET_MAX_LUN a besoin du
 * numéro d'interface lu dans les descripteurs, et la trace se compare alors d'un
 * bloc à la référence.
 *
 * Règle du projet : chaque requête envoyée cite sa source, section de spec et
 * trame de la capture de référence où le pilote Windows ou Brother l'envoie
 * lui-même. Rien n'est envoyé qui n'ait été observé dans 1b-enumeration.pcap
 * (énumération, prise de contact) ou dans 2a-gris-300-recto-sans-bm.pcap (scan),
 * 1e-gris-300-recto-verso.pcap et 1e-gris-600-recto.pcap (scans de l'étape 4),
 * sauf la Reset Recovery de bot.c, documentée par la spec Bulk-Only (BOT §5.3.4)
 * et réservée aux erreurs de transport, et RELEASE UNIT après une erreur de scan
 * (palliatif, voir scanner_feuille).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
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

/* Dépôts de la capture 2a, à l'octet près (tunnel.c les compare à sa liste). */
static const uint8_t depot_papier[10] = {0x08, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t depot_a0[10] = {0x28, 0x00, 0xa0, 0x00, 0x0a, 0x0d, 0x00, 0x00, 0x02, 0x00};

/* Ce que le pilote TWAIN demande avant de régler un scan (2a, trames 772 à
 * 1752) : trois fois de suite, l'opcode 0x08 (réponse 01 00 avec une feuille,
 * 00 00 sans ; déduit de 2a, 1e-sans-papier et 1e-nb-300-recto) puis READ type
 * 0xA0 (2 octets, 01 00 dans toutes les captures, sens inconnu). La signature
 * est relue avant chacune des cinq premières commandes, pas avant la sixième :
 * on le reproduit tel quel (trames 772, 937, 1096, 1258, 1418).
 *
 * Sans feuille, le pilote TWAIN attend qu'on en glisse une (1e-sans-papier) ;
 * nous, on s'arrête après la première réponse 00 00 et on le dit : attendre en
 * sondant le scanner serait une séquence qu'aucune capture ne montre.
 * Renvoie 1 si une feuille est engagée, 0 sinon, -1 en cas d'erreur. */
static int lire_papier(void)
{
    uint8_t d[2];
    for (int i = 0; i < 6; i++) {
        if (i < 5 && tunnel_signature() != 0)
            return -1;
        int papier = i % 2 == 0;
        if (tunnel_commande(papier ? depot_papier : depot_a0, 10, d, sizeof d) != 0)
            return -1;
        if (papier && d[0] == 0x00 && d[1] == 0x00) {
            trace_note("pas de feuille dans le chargeur (0x08 rend 00 00)");
            return 0;
        }
        if (d[0] != 0x01 || d[1] != 0x00) {
            fprintf(stderr, "%s : réponse %02x %02x jamais observée\n", papier ? "0x08" : "READ 0xA0", d[0], d[1]);
            return -1;
        }
    }
    trace_note("feuille engagée (0x08 rend 01 00, READ 0xA0 rend 01 00)");
    return 1;
}

/* Dépôts du scan, tunnel.c les compare octet pour octet à ceux de 2a. */
static const uint8_t depot_send_95[12] = {0x2a, 0x00, 0x95, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
static const uint8_t depot_send_96[12] = {0x2a, 0x00, 0x96, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00};
static const uint8_t depot_send_83[28] = {0x2a, 0x00, 0x83, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00,
                                          0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00};
static const uint8_t depot_fenetre[89] = {
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47,
    0x00, 0x00, 0x01, 0x2c, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x80,
    0x00, 0x00, 0x41, 0xa0, 0x80, 0x80, 0x80, 0x05, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0x1d, 0xe0, 0xff, 0x00, 0x1e, 0x60, 0x10, 0x68, 0x10, 0x00, 0x00, 0x64, 0x00,
    0x64, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t depot_reserve[10] = {0x16};
static const uint8_t depot_scan[10] = {0x1b, 0x00, 0x00, 0x00, 0x00, 0x80};
static const uint8_t depot_lire_image[10] = {0x28, 0x00, 0x00, 0x00, 0x0a, 0x0d, 0x1f, 0xea, 0xe0, 0x00};
static const uint8_t depot_release[10] = {0x17};

/* Étape 4. Fenêtre et READ du recto-verso (1e-gris-300-recto-verso, trames 2500
 * et 2811) et fenêtre du 600 dpi (1e-gris-600-recto trame 2718, dont le READ est
 * celui de 2a, trame 3033). Différences avec 2a : tunnel.c, protocole.md §3 et §6. */
static const uint8_t depot_fenetre_rv[89] = {
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47,
    0x00, 0x00, 0x01, 0x2c, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x80,
    0x00, 0x00, 0x43, 0xbc, 0x80, 0x80, 0x80, 0x05, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0x1d, 0xe0, 0xff, 0x00, 0x1e, 0x60, 0x21, 0xe0, 0x10, 0x00, 0x00, 0x64, 0x00,
    0x64, 0x00, 0x64, 0x10, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t depot_lire_image_rv[10] = {0x28, 0x00, 0x00, 0x00, 0x0a, 0x0d, 0x1e, 0x60, 0x00, 0x00};
static const uint8_t depot_fenetre_600[89] = {
    0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47,
    0x00, 0x00, 0x01, 0x2c, 0x02, 0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x80,
    0x00, 0x00, 0x41, 0xa0, 0x80, 0x80, 0x80, 0x05, 0x08, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0x1d, 0xe0, 0xff, 0x00, 0x1e, 0x60, 0x20, 0xd0, 0x10, 0x00, 0x00, 0x64, 0x00,
    0x64, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* Les trois façons de scanner qu'une capture montre de bout en bout. Pas de
 * recto-verso à 600 dpi : aucune capture, donc aucune fenêtre à rejouer
 * (tunnel.c la refuserait de toute façon). */
struct mode_scan {
    const char *nom;
    const uint8_t *fenetre;   /* SET WINDOW, 89 octets */
    const uint8_t *lire_image; /* READ image, 10 octets */
    int recto_verso;          /* 1 : les blocs alternent recto et verso (protocole.md §6) */
};
static const struct mode_scan mode_recto = {"recto 300 dpi (2a)", depot_fenetre, depot_lire_image, 0};
static const struct mode_scan mode_rv = {"recto-verso 300 dpi (1e-gris-300-recto-verso)", depot_fenetre_rv,
                                         depot_lire_image_rv, 1};
static const struct mode_scan mode_600 = {"recto 600 dpi (1e-gris-600-recto)", depot_fenetre_600, depot_lire_image,
                                          0};

/* Délai sans nouveau bloc au-delà duquel on abandonne. Dans 2a, le premier bloc
 * arrive 1,9 s après le dépôt de READ (908 sondages), les suivants toutes les
 * 0,18 s ; 30 s laissent une large marge sans attendre indéfiniment. */
#define ATTENTE_BLOC_MS 30000ULL
#define TAILLE_LECTURE 65536u /* taille des lectures 0xC3 du pilote Brother (2a, 52325) */
#define VOLUME_BLOC_MAX (16u << 20) /* garde-fou : 622 080 o dans toutes les captures */
/* Garde-fou sur la page : 65 blocs au plus dans les captures (A4 à 600 dpi,
 * 1e-gris-600-recto) ; 200 blocs, environ 124 Mo, protègent le disque d'un
 * scanner qui annoncerait des blocs sans fin. */
#define BLOCS_MAX 200

/* Ctrl+C pendant un scan : au lieu de tuer le programme, qui laisserait l'unité
 * réservée et la feuille engagée, on lève ce drapeau ; la boucle de lecture
 * s'arrête au tour suivant et RELEASE UNIT part comme après une erreur. */
static volatile LONG interrompu;

static BOOL WINAPI sur_ctrl_c(DWORD evenement)
{
    if (evenement != CTRL_C_EVENT && evenement != CTRL_BREAK_EVENT)
        return FALSE;
    InterlockedExchange(&interrompu, 1);
    return TRUE;
}

/* Lit les blocs d'image jusqu'à la fin de page (protocole.md §4) et les écrit
 * dans faces[0], ou, en recto-verso, alternativement dans faces[0] (recto) et
 * faces[1] (verso) : le scanner commence par un bloc recto et alterne, sans rien
 * dans l'état du bloc qui dise la face (protocole.md §6). Les octets sont écrits
 * tels quels, le verso encore en miroir : le redresser est l'affaire du rendu
 * (convertir --verso). Renvoie le nombre d'octets écrits, ou -1. */
static long long lire_page(FILE *faces[2], const struct mode_scan *m)
{
    static uint8_t tampon[TAILLE_LECTURE];
    long long total = 0;
    int blocs = 0;
    /* Premier READ image, 2a trame 2373 : dépôt sans lecture de statut. */
    if (tunnel_deposer(m->lire_image, 10) != 0)
        return -1;
    ULONGLONG depuis = GetTickCount64();
    for (;;) {
        struct etat_bloc b;
        if (interrompu) {
            fprintf(stderr, "scan interrompu (Ctrl+C)\n");
            return -1;
        }
        if (tunnel_etat_bloc(&b) != 0)
            return -1;
        if (b.etat == 3) /* fin de page, 2a trame 120206 */
            break;
        if (b.etat == 0) {
            /* Pas prêt : le pilote Brother relit aussitôt (2a, trames 2418 à 52293). */
            if (GetTickCount64() - depuis > ATTENTE_BLOC_MS) {
                fprintf(stderr, "aucun bloc depuis %llu s, abandon\n", ATTENTE_BLOC_MS / 1000);
                return -1;
            }
            continue;
        }
        if (b.etat != 1 || b.volume == 0 || b.volume > VOLUME_BLOC_MAX) {
            fprintf(stderr, "état de bloc jamais observé : %u, %llu octets\n", b.etat, b.volume);
            return -1;
        }
        /* Bloc prêt (2a trame 52307) : lectures 0xC3 de 64 Kio depuis l'adresse
         * annoncée, la dernière plus courte (trames 52325 à 52394). */
        uint32_t adresse = b.adresse;
        FILE *f = faces[m->recto_verso ? blocs % 2 : 0];
        for (unsigned long long reste = b.volume; reste;) {
            uint32_t n = reste > TAILLE_LECTURE ? TAILLE_LECTURE : (uint32_t)reste;
            if (tampon_lire(adresse, tampon, n) != 0)
                return -1;
            if (fwrite(tampon, 1, n, f) != n) {
                fprintf(stderr, "écriture de l'image impossible\n");
                return -1;
            }
            adresse += n;
            reste -= n;
        }
        total += (long long)b.volume;
        if (++blocs >= BLOCS_MAX) {
            fprintf(stderr, "plus de %d blocs : page anormalement longue, abandon\n", BLOCS_MAX);
            return -1;
        }
        /* Statut du READ (trames 52424 à 52436), puis READ suivant (52478). */
        if (tunnel_statut() != 0 || tunnel_deposer(m->lire_image, 10) != 0)
            return -1;
        depuis = GetTickCount64();
    }
    if (m->recto_verso && blocs % 2) {
        /* 70 blocs par feuille, 35 par face, dans 1e-gris-300-recto-verso. */
        fprintf(stderr, "recto-verso : %d blocs, nombre impair jamais observé\n", blocs);
        return -1;
    }
    trace_note("fin de page : %d blocs, %lld octets", blocs, total);
    return total;
}

/* Scan d'une feuille, rejoué de la capture du mode choisi (2a pour le recto à
 * 300 dpi : pilote TWAIN, Button Manager arrêté, trames 1753 à 120868) : les
 * réglages (trois SEND vendeur, SET WINDOW), RESERVE UNIT, SCAN, la boucle de
 * lecture, puis RELEASE UNIT. Chaque dépôt est identique, à l'octet près, à
 * celui de la capture. La fenêtre demande du RVB : le gris se tire du plan vert,
 * sur le PC (étape 3f).
 *
 * Accord écrit de David du 25/10/2026 (« go », en réponse à la demande du fil
 * de l'étape 3) pour les trois SEND vendeur, dont l'effet exact reste inconnu
 * (CLAUDE.md) : le pilote TWAIN les envoie avec ces octets avant chaque scan,
 * dans toutes les captures, recto-verso et 600 dpi compris.
 *
 * Dès que RESERVE UNIT a été tenté, toute erreur tente RELEASE UNIT avant de
 * rendre la main, pour ne pas laisser le scanner réservé. C'est un palliatif :
 * aucune capture ne montre RELEASE après une erreur, ni au milieu d'une page
 * (READ en attente, feuille engagée) ; SCSI-2 ne fait pas une erreur d'un
 * RELEASE sans réservation, et c'est la commande que le pilote Brother envoie
 * pour finir. Ctrl+C passe par le même chemin (sur_ctrl_c).
 *
 * faces[0] reçoit le recto, faces[1] le verso en recto-verso. Renvoie le
 * nombre d'octets lus, 0 s'il n'y a pas de feuille, -1 en cas d'erreur. */
static long long scanner_feuille(FILE *faces[2], const struct mode_scan *m)
{
    int r = lire_papier();
    if (r == 0) {
        fprintf(stderr, "pas de feuille dans le chargeur\n");
        return 0;
    }
    /* Réglages, 2a trames 1753 à 2171 : chacun déposé puis son statut lu. */
    if (r != 1 || tunnel_commande(depot_send_95, sizeof depot_send_95, NULL, 0) != 0 ||
        tunnel_commande(depot_send_96, sizeof depot_send_96, NULL, 0) != 0 ||
        tunnel_commande(depot_send_83, sizeof depot_send_83, NULL, 0) != 0 ||
        tunnel_commande(m->fenetre, 89, NULL, 0) != 0)
        return -1;
    /* RESERVE UNIT (trame 2177), SCAN (2276), lecture, RELEASE (120248). RELEASE
     * part dès que RESERVE a été tenté, même si son statut n'a pas été lu. */
    SetConsoleCtrlHandler(sur_ctrl_c, TRUE);
    long long total = -1;
    if (tunnel_commande(depot_reserve, sizeof depot_reserve, NULL, 0) == 0 &&
        tunnel_commande(depot_scan, sizeof depot_scan, NULL, 0) == 0)
        total = lire_page(faces, m);
    int liberee = tunnel_commande(depot_release, sizeof depot_release, NULL, 0) == 0;
    SetConsoleCtrlHandler(sur_ctrl_c, FALSE);
    if (!liberee) {
        fprintf(stderr, "RELEASE UNIT a échoué : débrancher et rebrancher le scanner\n");
        return -1;
    }
    return total;
}

/* Attente de la feuille suivante, comme le pilote TWAIN entre deux feuilles
 * (1e-gris-300-recto-verso, trames 122627 à 148287) : le dépôt 0x08, une fois
 * par seconde, jusqu'à la réponse 01 00 (feuille engagée). Le pilote y a
 * attendu 28 s ; on abandonne après ATTENTE_FEUILLE_S. Renvoie 1 si une
 * feuille est arrivée, 0 sinon, -1 en cas d'erreur. */
#define ATTENTE_FEUILLE_S 60
static int attendre_feuille(void)
{
    printf("glissez la feuille suivante (%d s au plus)\n", ATTENTE_FEUILLE_S);
    fflush(stdout);
    for (int s = 0; s < ATTENTE_FEUILLE_S && !interrompu; s++) {
        uint8_t d[2];
        Sleep(1000); /* intervalle du pilote : 1,0 s entre les trames 122627, 123538 et 124457 */
        if (tunnel_commande(depot_papier, sizeof depot_papier, d, sizeof d) != 0)
            return -1;
        if (d[0] == 0x01 && d[1] == 0x00)
            return 1;
        if (d[0] != 0x00 || d[1] != 0x00) {
            fprintf(stderr, "0x08 : réponse %02x %02x jamais observée\n", d[0], d[1]);
            return -1;
        }
    }
    return 0;
}

/* Fichier brut d'une face, créé sans jamais en écraser un : le nom donné tel
 * quel pour une seule feuille en recto seul (comme à l'étape 3), sinon le nom
 * sans « .brut », suivi de -pN pour la feuille N si l'on en scanne plusieurs, et
 * de -recto ou -verso en recto-verso, puis « .brut ». */
static FILE *creer_face(const char *sortie, int feuille, int feuilles, int recto_verso, int verso, char *nom,
                        size_t lg)
{
    size_t base = strlen(sortie);
    if (base >= 5 && _stricmp(sortie + base - 5, ".brut") == 0)
        base -= 5;
    char p[16] = "", f[8] = "";
    if (feuilles > 1)
        sprintf_s(p, sizeof p, "-p%d", feuille);
    if (recto_verso)
        strcpy_s(f, sizeof f, verso ? "-verso" : "-recto");
    if (feuilles == 1 && !recto_verso)
        strcpy_s(nom, lg, sortie);
    else if (sprintf_s(nom, lg, "%.*s%s%s.brut", (int)base, sortie, p, f) < 0)
        return NULL;
    int fd;
    if (_sopen_s(&fd, nom, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _SH_DENYWR, _S_IREAD | _S_IWRITE) != 0) {
        fprintf(stderr, "impossible de créer %s (existe-t-il déjà ?)\n", nom);
        return NULL;
    }
    FILE *fichier = _fdopen(fd, "wb");
    if (!fichier)
        _close(fd);
    return fichier;
}

/* Scan de une à plusieurs feuilles dans le mode choisi. Entre deux feuilles, on
 * attend la suivante comme le pilote TWAIN, puis toute la séquence repart :
 * présence du papier, réglages, RESERVE, SCAN… (1e-gris-300-recto-verso, de la
 * trame 148287 à 149859, la même suite que pour la première feuille). */
static int scanner_feuilles(const char *sortie, const struct mode_scan *m, int feuilles)
{
    trace_note("scan : %s, %d feuille(s)", m->nom, feuilles);
    for (int feuille = 1; feuille <= feuilles; feuille++) {
        if (feuille > 1) {
            int r = attendre_feuille();
            if (r <= 0) {
                if (r == 0)
                    fprintf(stderr, "pas de feuille %d : arrêt après %d feuille(s)\n", feuille, feuille - 1);
                return r == 0 && feuille > 1 ? 0 : -1;
            }
        }
        char noms[2][MAX_PATH];
        FILE *faces[2] = {NULL, NULL};
        int nfaces = m->recto_verso ? 2 : 1, ok = 1;
        for (int i = 0; i < nfaces && ok; i++)
            ok = (faces[i] = creer_face(sortie, feuille, feuilles, m->recto_verso, i, noms[i], MAX_PATH)) != NULL;
        long long total = ok ? scanner_feuille(faces, m) : -1;
        for (int i = 0; i < nfaces; i++)
            if (faces[i] && fclose(faces[i]) != 0)
                total = -1;
        if (total <= 0) {
            for (int i = 0; i < nfaces; i++) {
                if (!faces[i])
                    continue;
                if (total == 0)
                    remove(noms[i]); /* rien n'a été écrit : le nom reste libre pour un nouvel essai */
                else
                    fprintf(stderr, "%s : image incomplète ou absente, à ne pas convertir telle quelle\n", noms[i]);
            }
            return -1;
        }
        for (int i = 0; i < nfaces; i++)
            printf("%s : %lld lignes de 3 × 2592 points%s\n", noms[i], total / nfaces / 7776,
                   m->recto_verso ? (i ? " (verso, en miroir : convertir --verso)" : " (recto)") : "");
    }
    return 0;
}

static void usage(void)
{
    fprintf(stderr, "usage : ds720d descripteurs|lun|inquiry|etat|papier [--trace FICHIER]\n"
                    "        ds720d scan --sortie FICHIER.brut [--recto-verso | --ppp 600] [--feuilles N]\n"
                    "                    [--trace FICHIER]\n");
}

int main(int argc, char **argv)
{
    const char *commande = NULL, *chemin_trace = NULL, *sortie = NULL;
    int recto_verso = 0, ppp = 300, feuilles = 1;
    SetConsoleOutputCP(CP_UTF8); /* la trace est en UTF-8 */

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trace") == 0 && i + 1 < argc)
            chemin_trace = argv[++i];
        else if (strcmp(argv[i], "--sortie") == 0 && i + 1 < argc)
            sortie = argv[++i];
        else if (strcmp(argv[i], "--recto-verso") == 0)
            recto_verso = 1;
        else if (strcmp(argv[i], "--ppp") == 0 && i + 1 < argc)
            ppp = atoi(argv[++i]);
        else if (strcmp(argv[i], "--feuilles") == 0 && i + 1 < argc)
            feuilles = atoi(argv[++i]);
        else if (!commande)
            commande = argv[i];
        else {
            usage();
            return 2;
        }
    }
    /* Niveau atteint par la commande : 1 descripteurs, 2 GET_MAX_LUN, 3 INQUIRY,
     * 4 prise de contact par 0xC5, 5 présence du papier, 6 scan d'une page. */
    int niveau = 0;
    if (commande && strcmp(commande, "descripteurs") == 0)
        niveau = 1;
    else if (commande && strcmp(commande, "lun") == 0)
        niveau = 2;
    else if (commande && strcmp(commande, "inquiry") == 0)
        niveau = 3;
    else if (commande && strcmp(commande, "etat") == 0)
        niveau = 4;
    else if (commande && strcmp(commande, "papier") == 0)
        niveau = 5;
    else if (commande && strcmp(commande, "scan") == 0 && sortie)
        niveau = 6;
    /* Recto-verso à 600 dpi : aucune capture, donc refusé (voir mode_scan). */
    if ((ppp != 300 && ppp != 600) || (recto_verso && ppp == 600) || feuilles < 1 || feuilles > 50 ||
        (niveau != 6 && (recto_verso || ppp != 300 || feuilles != 1)))
        niveau = 0;
    const struct mode_scan *mode = recto_verso ? &mode_rv : ppp == 600 ? &mode_600 : &mode_recto;
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
    if (r == 0 && niveau == 6)
        r = scanner_feuilles(sortie, mode, feuilles);
    if (r == 0 && niveau == 5) {
        int papier = lire_papier();
        if (papier >= 0)
            printf("%s\n", papier ? "feuille engagée" : "pas de feuille");
        r = papier < 0 ? -1 : 0;
    }
    periph_fermer();
    trace_fermer();
    return r == 0 ? 0 : 1;
}
