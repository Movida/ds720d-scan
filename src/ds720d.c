/*
 * ds720d.c : programme qui parle au scanner Brother DS-720D par WinUSB.
 *
 * Usage :
 *   ds720d descripteurs [--trace FICHIER]
 *   ds720d lun [--trace FICHIER]
 *
 * Chaque commande refait les précédentes, dans l'ordre où Windows énumère le
 * scanner (1b) : descripteurs, puis GET_MAX_LUN. Pourquoi enchaîner plutôt
 * qu'isoler chaque requête : GET_MAX_LUN a besoin du numéro d'interface lu dans
 * les descripteurs, et la trace se compare alors d'un bloc à la référence.
 *
 * Règle du projet : chaque requête envoyée cite sa source, section de spec et
 * trame de la capture de référence où le pilote Windows l'envoie lui-même.
 * Rien n'est envoyé qui n'ait été observé dans 1b-enumeration.pcap.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "peripherique.h"
#include "trace.h"

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
    for (size_t i = 0; i + 2 <= (size_t)n && d[i] >= 2; i += d[i]) {
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

static void usage(void)
{
    fprintf(stderr, "usage : ds720d descripteurs|lun [--trace FICHIER]\n");
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
    /* Niveau atteint par la commande : 1 descripteurs, 2 GET_MAX_LUN. */
    int niveau = 0;
    if (commande && strcmp(commande, "descripteurs") == 0)
        niveau = 1;
    else if (commande && strcmp(commande, "lun") == 0)
        niveau = 2;
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
    periph_fermer();
    trace_fermer();
    return r == 0 ? 0 : 1;
}
