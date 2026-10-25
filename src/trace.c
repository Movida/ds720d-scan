/*
 * trace.c : écriture de la trace au format commun (docs/format-trace.md).
 *
 * Le texte produit reprend celui de banc/analyse_capture.py pour tout échange qui
 * réussit (SETUP, CTRL-IN, CBW, DATA-IN, CSW et leurs décodages), pour que
 * banc/compare_traces.py puisse confronter les deux traces sans traduction. Écarts
 * voulus ou connus, listés dans docs/format-trace.md : lignes ERREUR (code Win32
 * au lieu de USBD_STATUS), ligne URB pour le seul déblocage d'endpoint, texte du
 * numéro de série masqué, et
 * quelques cas limites (NUL dans un texte). Chaque décodage cite la section de
 * spec qu'il applique, comme dans l'analyseur.
 *
 * Pourquoi décoder en C plutôt que tracer seulement les octets bruts et décoder
 * après coup avec l'analyseur Python : on veut que notre programme « comprenne »
 * lui-même ce qu'il reçoit (c'est le but de l'étape), et une trace lisible sur le
 * moment évite d'enchaîner deux outils à chaque essai sur le scanner.
 */
#include "trace.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* Longueur maximale d'une ligne : le pire cas est un descripteur inconnu de
 * 255 octets écrit en entier (3 caractères par octet). */
#define LG_LIGNE 2048

/* Octets de données montrés par ligne, comme l'option --octets 32 de l'analyseur. */
#define OCTETS_MAX 32

/* Préfixe des lignes de détail : alignées sous la colonne « détail ». */
#define SUITE "                                    | "

static FILE *fichier;           /* copie de la trace sur disque, ou NULL */
static unsigned numero;         /* numéro d'ordre de la ligne d'évènement (colonne « trame ») */
static LARGE_INTEGER t0, freq;  /* origine des temps et fréquence du compteur */

/* État suivi entre deux appels, comme dans le décodeur de l'analyseur. */
static uint8_t i_serie;         /* iSerialNumber lu dans le descripteur DEVICE, 0 si inconnu */
static int cbw_en_cours;        /* un CBW attend son CSW */
static uint32_t cbw_tag;
static uint32_t cbw_lg_donnees; /* dCBWDataTransferLength du CBW en cours */
static uint8_t cbw_cdb[16];
static size_t cbw_lg_cdb;

/* ------------------------------------------------------------------------- */
/* Outils                                                                    */
/* ------------------------------------------------------------------------- */

static uint16_t le16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* Octets en hexadécimal séparés par des espaces ; au-delà de maxi (si maxi >= 0),
 * on coupe et on ajoute « … », comme hexa() dans l'analyseur. */
static void hexa(char *dst, size_t taille, const uint8_t *o, size_t lg, int maxi)
{
    size_t n = (maxi >= 0 && lg > (size_t)maxi) ? (size_t)maxi : lg;
    size_t pos = 0;
    dst[0] = '\0';
    for (size_t i = 0; i < n && pos + 4 < taille; i++)
        pos += (size_t)snprintf(dst + pos, taille - pos, i ? " %02x" : "%02x", o[i]);
    if (n < lg)
        snprintf(dst + pos, taille - pos, " \xE2\x80\xA6"); /* « … » en UTF-8 */
}

static void sortir(const char *texte)
{
    fputs(texte, stdout);
    if (fichier)
        fputs(texte, fichier);
}

static void ligne(const char *evenement, const char *detail)
{
    LARGE_INTEGER t;
    char buf[LG_LIGNE + 64];
    QueryPerformanceCounter(&t);
    double s = (double)(t.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
    /* Mêmes largeurs que Decodeur.ligne() de l'analyseur. L'adresse USB vaut 0 :
     * WinUSB ne la donne pas, et elle ne sert pas à la comparaison. */
    snprintf(buf, sizeof buf, "%-8u %12.6f  %3u  %-10s %s\n", ++numero, s, 0u, evenement, detail);
    sortir(buf);
}

static void suite(const char *detail)
{
    char buf[LG_LIGNE + 64];
    snprintf(buf, sizeof buf, SUITE "%s\n", detail);
    sortir(buf);
}

/* ------------------------------------------------------------------------- */
/* Paquets SETUP : USB 2.0 §9.3, table 9-2 ; requêtes standard, table 9-4 ;   */
/* types de descripteur, table 9-5 ; requêtes de classe BOT §3.1 et §3.2.     */
/* ------------------------------------------------------------------------- */

static const char *requete_standard(uint8_t req)
{
    static const char *noms[] = {
        "GET_STATUS", "CLEAR_FEATURE", NULL, "SET_FEATURE", NULL, "SET_ADDRESS",
        "GET_DESCRIPTOR", "SET_DESCRIPTOR", "GET_CONFIGURATION", "SET_CONFIGURATION",
        "GET_INTERFACE", "SET_INTERFACE", "SYNCH_FRAME",
    };
    return req < sizeof noms / sizeof noms[0] ? noms[req] : NULL;
}

static const char *type_descripteur(uint8_t type)
{
    switch (type) {
    case 1: return "DEVICE";
    case 2: return "CONFIGURATION";
    case 3: return "STRING";
    case 4: return "INTERFACE";
    case 5: return "ENDPOINT";
    case 6: return "DEVICE_QUALIFIER";
    case 7: return "OTHER_SPEED_CONFIGURATION";
    case 8: return "INTERFACE_POWER";
    case 0x0F: return "BOS";
    default: return NULL;
    }
}

static void decrire_setup(char *dst, size_t taille, const uint8_t s[8])
{
    uint8_t bm = s[0], req = s[1];
    uint16_t valeur = le16(s + 2), index = le16(s + 4), longueur = le16(s + 6);
    const char *sens = (bm & 0x80) ? "IN" : "OUT";
    unsigned genre = (bm >> 5) & 3; /* bmRequestType bits 6..5 : 0 standard, 1 classe, 2 vendeur */
    char nom[32];

    if (genre == 0) {
        const char *n = requete_standard(req);
        if (n)
            snprintf(nom, sizeof nom, "%s", n);
        else
            snprintf(nom, sizeof nom, "STANDARD_0x%02X", req);
        if (req == 6) { /* GET_DESCRIPTOR : wValue = type << 8 | index (§9.4.3) */
            const char *t = type_descripteur((uint8_t)(valeur >> 8));
            char tnom[8];
            if (!t) {
                snprintf(tnom, sizeof tnom, "0x%02X", valeur >> 8);
                t = tnom;
            }
            snprintf(dst, taille, "%s %s index=%u langue=0x%04X wLength=%u (%s)",
                     nom, t, valeur & 0xFFu, index, longueur, sens);
            return;
        }
        if (req == 9) {
            snprintf(dst, taille, "%s valeur=%u", nom, valeur);
            return;
        }
        if (req == 11) {
            snprintf(dst, taille, "%s interface=%u alternatif=%u", nom, index, valeur);
            return;
        }
    } else if (genre == 1) {
        if (req == 0xFF)
            snprintf(nom, sizeof nom, "BULK_ONLY_RESET");
        else if (req == 0xFE)
            snprintf(nom, sizeof nom, "GET_MAX_LUN");
        else
            snprintf(nom, sizeof nom, "CLASSE_0x%02X", req);
    } else if (genre == 2) {
        snprintf(nom, sizeof nom, "VENDEUR_0x%02X", req);
    } else {
        snprintf(nom, sizeof nom, "R\xC3\x89SERV\xC3\x89_0x%02X", req); /* RÉSERVÉ */
    }
    snprintf(dst, taille, "%s wValue=0x%04X wIndex=0x%04X wLength=%u (%s)",
             nom, valeur, index, longueur, sens);
}

/* ------------------------------------------------------------------------- */
/* Descripteurs : USB 2.0 §9.6. Une réponse CONFIGURATION contient la         */
/* configuration puis ses interfaces et endpoints à la suite (§9.4.3).        */
/* ------------------------------------------------------------------------- */

static void decrire_descripteurs(const uint8_t *o, size_t lg_total, uint8_t index_chaine)
{
    static const char *types_endpoint[] = {"contr\xC3\xB4le", "isochrone", "bulk", "interruption"};
    char buf[LG_LIGNE], hx[LG_LIGNE];
    size_t i = 0;

    while (i + 2 <= lg_total) {
        uint8_t lg = o[i], typ = o[i + 1];
        const uint8_t *d = o + i;
        const char *tn = type_descripteur(typ);
        if (lg < 2) {
            snprintf(buf, sizeof buf, "bLength=%u invalide \xC3\xA0 l'octet %zu, arr\xC3\xAAt", lg, i);
            suite(buf);
            break;
        }
        if (i + lg > lg_total) {
            /* Réponse plus courte que bLength : normal quand Windows ne demande que
             * 2 octets pour lire bLength d'abord (trame 19204 de 1b). */
            if (tn)
                snprintf(buf, sizeof buf, "%s incomplet (%zu/%u o)", tn, lg_total - i, lg);
            else
                snprintf(buf, sizeof buf, "0x%x incomplet (%zu/%u o)", typ, lg_total - i, lg);
            suite(buf);
            break;
        }
        if (typ == 1 && lg >= 18) { /* DEVICE, table 9-8 */
            uint16_t bcd = le16(d + 2);
            snprintf(buf, sizeof buf,
                     "DEVICE USB %x.%02x classe=%02X/%02X/%02X bMaxPacketSize0=%u VID=0x%04X "
                     "PID=0x%04X bcdDevice=0x%04X iManufacturer=%u iProduct=%u iSerial=%u "
                     "configurations=%u",
                     bcd >> 8, bcd & 0xFFu, d[4], d[5], d[6], d[7], le16(d + 8), le16(d + 10),
                     le16(d + 12), d[14], d[15], d[16], d[17]);
        } else if (typ == 2 && lg >= 9) { /* CONFIGURATION, table 9-10 ; bMaxPower par 2 mA */
            snprintf(buf, sizeof buf,
                     "CONFIGURATION wTotalLength=%u interfaces=%u bConfigurationValue=%u "
                     "attributs=0x%02X courant max=%u mA",
                     le16(d + 2), d[4], d[5], d[7], d[8] * 2u);
        } else if (typ == 4 && lg >= 9) { /* INTERFACE, table 9-12 */
            snprintf(buf, sizeof buf, "INTERFACE n\xC2\xB0%u alt=%u endpoints=%u classe=%02X/%02X/%02X",
                     d[2], d[3], d[4], d[5], d[6], d[7]);
        } else if (typ == 5 && lg >= 7) { /* ENDPOINT, table 9-13 ; bit 7 de l'adresse = sens */
            snprintf(buf, sizeof buf, "ENDPOINT 0x%02X (%s, %s) wMaxPacketSize=%u bInterval=%u",
                     d[2], (d[2] & 0x80) ? "IN" : "OUT", types_endpoint[d[3] & 3], le16(d + 4), d[6]);
        } else if (typ == 3 && index_chaine == 0) { /* §9.6.7 : liste de LANGID sur 16 bits */
            size_t pos = (size_t)snprintf(buf, sizeof buf, "STRING 0 : langues ");
            for (size_t k = 0; k < ((size_t)lg - 2) / 2; k++)
                pos += (size_t)snprintf(buf + pos, sizeof buf - pos, k ? ", 0x%04X" : "0x%04X",
                                        le16(d + 2 + 2 * k));
        } else if (typ == 3) { /* §9.6.7 : texte en UTF-16LE */
            WCHAR w[128];
            char texte[512];
            int n = (lg - 2) / 2;
            memcpy(w, d + 2, (size_t)n * 2); /* copie : d + 2 n'est pas forcément aligné */
            int lt = WideCharToMultiByte(CP_UTF8, 0, w, n, texte, (int)sizeof texte - 4, NULL, NULL);
            lt = lt > 0 ? lt : 0;
            if ((lg - 2) % 2) { /* octet impair final : U+FFFD, comme errors="replace" */
                memcpy(texte + lt, "\xEF\xBF\xBD", 3);
                lt += 3;
            }
            texte[lt] = '\0';
            hexa(hx, sizeof hx, d + 2, (size_t)lg - 2, -1);
            snprintf(buf, sizeof buf, "STRING \xC2\xAB %s \xC2\xBB (%s)", texte, hx);
        } else {
            char tnom[16];
            if (!tn) {
                snprintf(tnom, sizeof tnom, "type 0x%02X", typ);
                tn = tnom;
            }
            hexa(hx, sizeof hx, d, lg, -1);
            snprintf(buf, sizeof buf, "%s %u o : %s", tn, lg, hx);
        }
        suite(buf);
        i += lg;
    }
}

/* ------------------------------------------------------------------------- */
/* SCSI : noms des opcodes (SPC-4, SBC-3, UFI 1.0) et réponses connues.       */
/* ------------------------------------------------------------------------- */

static void nom_opcode(char *dst, size_t taille, int op)
{
    /* Opcodes qui modifient le support ou le firmware : interdits par CLAUDE.md.
     * Cette liste, la même que celle de l'analyseur, ne sert qu'à signaler les
     * plus courants dans la trace ; le vrai garde-fou est la liste blanche de
     * bot.c, qui refuse tout opcode non observé avant l'envoi. */
    static const struct { uint8_t op; const char *nom; } dangereux[] = {
        {0x04, "FORMAT UNIT"}, {0x0A, "WRITE(6)"}, {0x2A, "WRITE(10)"},
        {0x2E, "WRITE AND VERIFY(10)"}, {0x3B, "WRITE BUFFER"}, {0xAA, "WRITE(12)"},
        {0x8A, "WRITE(16)"},
    };
    static const struct { uint8_t op; const char *nom; } connus[] = {
        {0x00, "TEST UNIT READY"}, {0x03, "REQUEST SENSE"}, {0x12, "INQUIRY"},
        {0x1A, "MODE SENSE(6)"}, {0x1B, "START STOP UNIT"}, {0x1E, "PREVENT ALLOW MEDIUM REMOVAL"},
        {0x23, "READ FORMAT CAPACITIES"}, {0x25, "READ CAPACITY(10)"}, {0x28, "READ(10)"},
        {0x5A, "MODE SENSE(10)"}, {0x9E, "SERVICE ACTION IN(16)"},
    };
    for (size_t k = 0; k < sizeof dangereux / sizeof dangereux[0]; k++)
        if (dangereux[k].op == op) {
            snprintf(dst, taille, "%s !! \xC3\x89" "CRITURE", dangereux[k].nom); /* ÉCRITURE */
            return;
        }
    for (size_t k = 0; k < sizeof connus / sizeof connus[0]; k++)
        if (connus[k].op == op) {
            snprintf(dst, taille, "%s", connus[k].nom);
            return;
        }
    if (op >= 0xC0) /* groupes 6 et 7 des codes d'opération : réservés aux fabricants (SPC-4) */
        snprintf(dst, taille, "VENDEUR 0x%02X", op);
    else
        snprintf(dst, taille, "opcode 0x%02X", op & 0xFF);
}

/* Les caractères ASCII que str.strip() de Python retire : espace, \t \n \v \f \r
 * et les séparateurs 0x1C à 0x1F. */
static int blanc(uint8_t c) { return c == ' ' || (c >= 0x09 && c <= 0x0D) || (c >= 0x1C && c <= 0x1F); }

/* Champ ASCII des données INQUIRY, sans les blancs de bourrage ; un octet
 * non ASCII devient U+FFFD, comme decode("ascii", errors="replace").strip().
 * Écart connu : un octet NUL au milieu coupe le texte ici, pas dans l'analyseur. */
static void texte_ascii(char *dst, size_t taille, const uint8_t *o, size_t lg)
{
    size_t debut = 0, fin = lg, pos = 0;
    while (debut < fin && blanc(o[debut]))
        debut++;
    while (fin > debut && blanc(o[fin - 1]))
        fin--;
    for (size_t k = debut; k < fin && pos + 4 < taille; k++) {
        if (o[k] < 0x80) {
            dst[pos++] = (char)o[k];
        } else {
            memcpy(dst + pos, "\xEF\xBF\xBD", 3);
            pos += 3;
        }
    }
    dst[pos] = '\0';
}

static void decrire_reponse_scsi(const uint8_t *d, size_t lg)
{
    char buf[LG_LIGNE];
    if (cbw_lg_cdb == 0 || lg == 0)
        return;
    if (cbw_cdb[0] == 0x03 && lg >= 14 && ((d[0] & 0x7F) == 0x70 || (d[0] & 0x7F) == 0x71)) {
        /* Sense au format fixe (SPC-4, « Fixed format sense data ») : clé octet 2,
         * ASC octet 12, ASCQ octet 13. Clés : SPC-4, « Sense key descriptions ». */
        static const char *cles[16] = {
            "NO SENSE", "RECOVERED ERROR", "NOT READY", "MEDIUM ERROR", "HARDWARE ERROR",
            "ILLEGAL REQUEST", "UNIT ATTENTION", "DATA PROTECT", "BLANK CHECK", "VENDOR SPECIFIC",
            NULL, "ABORTED COMMAND", NULL, NULL, "MISCOMPARE", NULL,
        };
        unsigned cle = d[2] & 0x0F;
        snprintf(buf, sizeof buf, "sense : cl\xC3\xA9 0x%X (%s) ASC/ASCQ = 0x%02X/0x%02X", cle,
                 cles[cle] ? cles[cle] : "?", d[12], d[13]);
        suite(buf);
        return;
    }
    if (cbw_cdb[0] == 0x25 && lg >= 8) {
        /* READ CAPACITY(10) (SBC-3) : dernier LBA et taille de bloc, gros-boutistes. */
        unsigned long long dernier = (unsigned long long)d[0] << 24 | d[1] << 16 | d[2] << 8 | d[3];
        unsigned long long bloc = (unsigned long long)d[4] << 24 | d[5] << 16 | d[6] << 8 | d[7];
        snprintf(buf, sizeof buf, "capacit\xC3\xA9 : %llu blocs de %llu o = %llu o", dernier + 1, bloc,
                 (dernier + 1) * bloc);
        suite(buf);
        return;
    }
    if (cbw_cdb[0] == 0x12 && cbw_lg_cdb > 1 && !(cbw_cdb[1] & 1) && lg >= 36) {
        /* Données INQUIRY standard (SPC-4, « Standard INQUIRY data ») : type de
         * périphérique sur 5 bits, bit RMB, vendeur 8..15, produit 16..31, révision 32..35. */
        char vendeur[64], produit[96], revision[32];
        texte_ascii(vendeur, sizeof vendeur, d + 8, 8);
        texte_ascii(produit, sizeof produit, d + 16, 16);
        texte_ascii(revision, sizeof revision, d + 32, 4);
        snprintf(buf, sizeof buf,
                 "INQUIRY : type 0x%02X, amovible=%u, vendeur \xC2\xAB %s \xC2\xBB, "
                 "produit \xC2\xAB %s \xC2\xBB, r\xC3\xA9vision \xC2\xAB %s \xC2\xBB",
                 d[0] & 0x1F, d[1] >> 7, vendeur, produit, revision);
        suite(buf);
    }
}

/* ------------------------------------------------------------------------- */
/* Protocole vendeur du DS-720D (docs/protocole.md) : même texte que la       */
/* section 5 de l'analyseur. Les chaînes de cette section sont écrites en     */
/* UTF-8 littéral (option /utf-8 du Makefile) plutôt qu'en échappements \x :  */
/* plus lisibles, et sans le piège d'un \xA9 suivi d'une lettre a à f, que le */
/* compilateur avalerait dans l'échappement.                                 */
/* ------------------------------------------------------------------------- */

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

/* Troisième octet k des sélecteurs 02 01 k et 02 02 k (docs/protocole.md §2). */
static const char *genre_reponse(uint8_t k)
{
    static const char *noms[] = {"données", "statut", "bloc d'image", "identifiant fabricant",
                                 "identifiant produit"};
    return k < sizeof noms / sizeof noms[0] ? noms[k] : NULL;
}

static void nom_selecteur(char *dst, size_t taille, const uint8_t s[3])
{
    const char *genre = genre_reponse(s[2]);
    if (s[0] == 0xFF && s[1] == 0x02 && s[2] == 0)
        snprintf(dst, taille, "signature");
    else if (s[0] == 0xFF && s[1] >= 0x03 && s[1] <= 0x06 && s[2] == 0)
        snprintf(dst, taille, "sondage d'état");
    else if (s[0] == 0x02 && s[1] == 0x03 && s[2] == 0)
        snprintf(dst, taille, "dépôt d'une commande");
    else if (s[0] == 0x02 && (s[1] == 0x01 || s[1] == 0x02) && genre)
        snprintf(dst, taille, "%s, %s", s[1] == 0x01 ? "en-tête de réponse" : "réponse", genre);
    else
        snprintf(dst, taille, "inconnu");
}

/* Ligne de détail sous un CBW 0xC3 ou 0xC5, avec les écarts à la forme connue
 * du CDB signalés par « !! », dans le même ordre que l'analyseur. */
static void decrire_cdb_vendeur(void)
{
    char buf[LG_LIGNE], nom[64];
    size_t pos;
    if (cbw_lg_cdb != 16) {
        snprintf(buf, sizeof buf, "!! CDB vendeur de %zu o (attendu 16)", cbw_lg_cdb);
        suite(buf);
        return;
    }
    uint32_t adresse = be32(cbw_cdb + 2), longueur = be32(cbw_cdb + 6);
    if (cbw_cdb[0] == 0xC5) {
        char sel[16];
        hexa(sel, sizeof sel, cbw_cdb + 10, 3, -1);
        nom_selecteur(nom, sizeof nom, cbw_cdb + 10);
        pos = (size_t)snprintf(buf, sizeof buf, "tunnel 0xC5, sélecteur %s : %s, %u o", sel, nom, longueur);
    } else {
        pos = (size_t)snprintf(buf, sizeof buf, "lecture 0xC3 à l'adresse 0x%08X, %u o", adresse, longueur);
    }
    if (cbw_cdb[1] != 0x07)
        pos += (size_t)snprintf(buf + pos, sizeof buf - pos, "  !! octet 1 = 0x%02X (attendu 07)", cbw_cdb[1]);
    if (cbw_cdb[13] | cbw_cdb[14] | cbw_cdb[15])
        pos += (size_t)snprintf(buf + pos, sizeof buf - pos, "  !! octets 13-15 non nuls");
    if (cbw_cdb[0] == 0xC5 && adresse)
        snprintf(buf + pos, sizeof buf - pos, "  !! adresse 0x%08X (attendue 0)", adresse);
    if (cbw_cdb[0] == 0xC3 && (cbw_cdb[10] | cbw_cdb[11] | cbw_cdb[12]))
        snprintf(buf + pos, sizeof buf - pos, "  !! octets 10-12 non nuls");
    suite(buf);
}

/* Détail des réponses 0xC5 qu'on sait lire (docs/protocole.md §2 et §4). */
static void decrire_reponse_vendeur(const uint8_t *d, size_t lg)
{
    char buf[LG_LIGNE];
    if (cbw_lg_cdb != 16 || cbw_cdb[0] != 0xC5)
        return;
    const uint8_t *s = cbw_cdb + 10;
    if (s[0] == 0xFF && s[1] == 0x02 && s[2] == 0 && lg == 4) {
        /* decode("ascii", errors="replace") : un octet non ASCII devient U+FFFD. */
        size_t pos = (size_t)snprintf(buf, sizeof buf, "signature « ");
        for (size_t k = 0; k < 4; k++) {
            if (d[k] < 0x80) {
                buf[pos++] = (char)d[k];
            } else {
                memcpy(buf + pos, "\xEF\xBF\xBD", 3);
                pos += 3;
            }
        }
        snprintf(buf + pos, sizeof buf - pos, " »");
        suite(buf);
    } else if (s[0] == 0x02 && s[1] == 0x02 && s[2] == 2 && lg == 24) {
        /* Six mots de 32 bits petit-boutistes : état, ?, ?, deux facteurs, adresse. */
        uint32_t etat = le32(d), a = le32(d + 12), b = le32(d + 16), adresse = le32(d + 20);
        const char *nom = etat == 0 ? "pas prêt" : etat == 1 ? "prêt" : etat == 3 ? "fin de page" : "?";
        snprintf(buf, sizeof buf, "bloc d'image : état %u (%s), %u × %u = %llu o, adresse 0x%08X",
                 etat, nom, a, b, (unsigned long long)a * b, adresse);
        suite(buf);
    } else if (s[0] == 0x02 && s[1] == 0x02 && (s[2] == 3 || s[2] == 4) && lg == 2) {
        snprintf(buf, sizeof buf, "identifiant 0x%04X", (unsigned)(d[0] << 8 | d[1])); /* gros-boutiste */
        suite(buf);
    } else if (s[0] == 0x02 && s[1] == 0x02 && s[2] == 1 && lg == 4) {
        snprintf(buf, sizeof buf, "statut de la commande : 0x%08X", le32(d));
        suite(buf);
    }
}

/* Vrai si le CBW en cours est un dépôt de commande par le tunnel (02 03 00). */
static int depot_en_cours(void)
{
    return cbw_en_cours && cbw_lg_cdb == 16 && cbw_cdb[0] == 0xC5 && cbw_cdb[10] == 0x02 &&
           cbw_cdb[11] == 0x03 && cbw_cdb[12] == 0x00;
}

/* Paramètres de SET WINDOW (SCSI-2 §15.2.7) : en-tête de 8 octets (longueur du
 * descripteur en octets 6-7), puis descripteur de fenêtre (table 282). */
static void decrire_fenetre(const uint8_t *p, size_t lg)
{
    static const char *compositions[] = {"noir et blanc 1 bit", "noir et blanc tramé", "gris multiniveau",
                                         "RVB 1 bit", "RVB tramé", "RVB multiniveau"};      /* table 283 */
    static const char *bourrages[] = {"aucun", "zéros jusqu'à l'octet", "uns jusqu'à l'octet",
                                      "tronqué à l'octet"};                                 /* table 284 */
    char buf[LG_LIGNE], hx[LG_LIGNE];
    if (lg < 8) {
        snprintf(buf, sizeof buf, "!! paramètres de SET WINDOW trop courts (%zu o)", lg);
        suite(buf);
        return;
    }
    size_t lg_desc = (size_t)(p[6] << 8 | p[7]);
    size_t lg_d = lg - 8 < lg_desc ? lg - 8 : lg_desc;
    const uint8_t *d = p + 8;
    if (lg_d < 40 || lg_d != lg_desc) {
        snprintf(buf, sizeof buf, "!! descripteur de fenêtre de %zu o (annoncé %zu)", lg_d, lg_desc);
        suite(buf);
        return;
    }
    uint32_t largeur = be32(d + 14), longueur = be32(d + 18);
    /* Unité des coordonnées : 1/1200 de pouce par défaut (SCSI-2 §15.3.3.1). */
    snprintf(buf, sizeof buf,
             "fenêtre %u, auto=%u : %u × %u ppp, origine (%u, %u), %u × %u unités (%.3f × %.3f po à 1/1200 po)",
             d[0], d[1] & 1u, (unsigned)(d[2] << 8 | d[3]), (unsigned)(d[4] << 8 | d[5]), be32(d + 6),
             be32(d + 10), largeur, longueur, largeur / 1200.0, longueur / 1200.0);
    suite(buf);
    snprintf(buf, sizeof buf, "luminosité 0x%02X, seuil 0x%02X, contraste 0x%02X, composition %02X (%s), "
             "%u bits par pixel", d[22], d[23], d[24], d[25], d[25] < 6 ? compositions[d[25]] : "réservé", d[26]);
    suite(buf);
    snprintf(buf, sizeof buf, "demi-teinte 0x%04X, RIF %u, bourrage %u (%s), ordre des bits 0x%04X, "
             "compression %02X/%02X", (unsigned)(d[27] << 8 | d[28]), d[29] >> 7, d[29] & 7u,
             (d[29] & 7) < 4 ? bourrages[d[29] & 7] : "réservé", (unsigned)(d[30] << 8 | d[31]), d[32], d[33]);
    suite(buf);
    hexa(hx, sizeof hx, d + 40, lg_d - 40, -1);
    snprintf(buf, sizeof buf, "octets vendeur (%zu) : %s", lg_d - 40, hx);
    suite(buf);
}

/* Lignes de détail sous le DATA-OUT d'un dépôt : la commande SCSI-2 emballée,
 * puis ses paramètres quand on sait les lire (docs/protocole.md §3). */
static void decrire_depot(const uint8_t *depot, size_t lg)
{
    /* Commandes de la table 277 de SCSI-2 (§15.2) ; 0x2A y est SEND, pas WRITE(10). */
    static const struct { uint8_t op; const char *nom, *section; } scanner[] = {
        {0x00, "TEST UNIT READY", "§8.2.16"}, {0x03, "REQUEST SENSE", "§8.2.14"}, {0x12, "INQUIRY", "§8.2.5"},
        {0x16, "RESERVE UNIT", "§10.2.10"},  {0x17, "RELEASE UNIT", "§10.2.9"},  {0x1B, "SCAN", "§15.2.5"},
        {0x24, "SET WINDOW", "§15.2.7"},     {0x25, "GET WINDOW", "§15.2.2"},    {0x28, "READ", "§15.2.4"},
        {0x2A, "SEND", "§15.2.6"},           {0x31, "OBJECT POSITION", "§15.2.3"},
        {0x34, "GET DATA BUFFER STATUS", "§15.2.1"},
    };
    static const struct { uint8_t op; const char *nom; } dangereux[] = {
        {0x04, "FORMAT UNIT"}, {0x0A, "WRITE(6)"}, {0x2E, "WRITE AND VERIFY(10)"},
        {0x3B, "WRITE BUFFER"}, {0x8A, "WRITE(16)"}, {0xAA, "WRITE(12)"},
    };
    char buf[LG_LIGNE], nom[96], hx[LG_LIGNE];
    if (lg < 10) {
        snprintf(buf, sizeof buf, "!! dépôt de %zu o (attendu au moins 10)", lg);
        suite(buf);
        return;
    }
    uint8_t op = depot[0];
    size_t lg_cdb = op < 0x20 ? 6 : 10; /* groupe 0 : 6 o, groupe 1 : 10 o (SCSI-2 §7.2.1) */
    const uint8_t *donnees = depot + 10;
    size_t lg_donnees = lg - 10;

    snprintf(nom, sizeof nom, "opcode 0x%02X (absent de la table 277 des scanners)", op);
    for (size_t k = 0; k < sizeof scanner / sizeof scanner[0]; k++)
        if (scanner[k].op == op)
            snprintf(nom, sizeof nom, "%s (SCSI-2 %s)", scanner[k].nom, scanner[k].section);
    for (size_t k = 0; k < sizeof dangereux / sizeof dangereux[0]; k++)
        if (dangereux[k].op == op)
            snprintf(nom, sizeof nom, "%s !! ÉCRITURE", dangereux[k].nom);
    hexa(hx, sizeof hx, depot, lg_cdb, -1);
    size_t pos = (size_t)snprintf(buf, sizeof buf, "commande emballée : %s, CDB[%zu]=%s", nom, lg_cdb, hx);
    for (size_t k = lg_cdb; k < 10; k++)
        if (depot[k]) {
            pos += (size_t)snprintf(buf + pos, sizeof buf - pos, "  !! zone de CDB non nulle après le CDB");
            break;
        }

    int serie = 0;
    if (op == 0x28 || op == 0x2A) {
        /* READ et SEND, tables 288 et 291 : type octet 2, qualificatif 4-5, longueur 6-8. */
        uint8_t type = depot[2];
        uint32_t n = (uint32_t)depot[6] << 16 | (uint32_t)depot[7] << 8 | depot[8];
        const char *t = type == 0 ? "image" : type == 1 ? "vendeur" : type == 2 ? "masque de demi-teinte"
                      : type == 3 ? "fonction gamma" : type >= 0x80 ? "vendeur" : "réservé"; /* table 289 */
        pos += (size_t)snprintf(buf + pos, sizeof buf - pos, ", type 0x%02X (%s), qualificatif 0x%04X, %u o", type,
                                t, (unsigned)(depot[4] << 8 | depot[5]), n);
        if (op == 0x2A && n != lg_donnees)
            snprintf(buf + pos, sizeof buf - pos, "  !! %zu o de données déposés", lg_donnees);
        serie = op == 0x2A && type == 0x85; /* date et numéro de série (Capture Tool) */
    } else if (op == 0x24) {
        uint32_t n = (uint32_t)depot[6] << 16 | (uint32_t)depot[7] << 8 | depot[8]; /* table 292 */
        pos += (size_t)snprintf(buf + pos, sizeof buf - pos, ", %u o de paramètres", n);
        if (n != lg_donnees)
            snprintf(buf + pos, sizeof buf - pos, "  !! %zu o déposés", lg_donnees);
    } else if (op == 0x1B) {
        /* SCAN, table 290 : octet 4 = longueur de la liste de fenêtres ; octet de
         * contrôle : bits 7-6 réservés au fabricant (SCSI-2 §7.2.7). */
        snprintf(buf + pos, sizeof buf - pos, ", liste de fenêtres de %u o, contrôle 0x%02X", depot[4], depot[5]);
    } else if (op < 0x20) {
        snprintf(buf + pos, sizeof buf - pos, ", octet 4 = %u", depot[4]);
    }
    suite(buf);

    if (op == 0x24) {
        decrire_fenetre(donnees, lg_donnees);
    } else if (serie) {
        suite("données : (numéro de série masqué)");
    } else if (op == 0x2A || lg_donnees) {
        hexa(hx, sizeof hx, donnees, lg_donnees, -1);
        snprintf(buf, sizeof buf, "données : %s", hx);
        suite(buf);
    }
}

/* ------------------------------------------------------------------------- */
/* Interface publique                                                        */
/* ------------------------------------------------------------------------- */

int trace_ouvrir(const char *chemin)
{
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);
    numero = 0;
    i_serie = 0;
    cbw_en_cours = 0;
    if (chemin) {
        /* Binaire : des fins de ligne \n seules, comme la sortie de l'analyseur
         * redirigée par Python ; compare_traces.py accepte les deux. */
        if (fopen_s(&fichier, chemin, "wb") != 0)
            return -1;
    }
    sortir("# trame     temps (s)  adr  \xC3\xA9v\xC3\xA9nement  d\xC3\xA9tail\n");
    return 0;
}

void trace_fermer(void)
{
    if (fichier) {
        fclose(fichier);
        fichier = NULL;
    }
}

void trace_note(const char *format, ...)
{
    char buf[LG_LIGNE];
    va_list ap;
    va_start(ap, format);
    buf[0] = '#';
    buf[1] = ' ';
    vsnprintf(buf + 2, sizeof buf - 3, format, ap);
    va_end(ap);
    strcat_s(buf, sizeof buf, "\n");
    sortir(buf);
}

void trace_setup(const uint8_t setup[8])
{
    char hx[32], dec[256], buf[LG_LIGNE];
    hexa(hx, sizeof hx, setup, 8, -1);
    decrire_setup(dec, sizeof dec, setup);
    snprintf(buf, sizeof buf, "%s  %s", hx, dec);
    ligne("SETUP", buf);
}

void trace_ctrl_in(const uint8_t setup[8], const uint8_t *donnees, size_t lg)
{
    char hx[LG_LIGNE], buf[LG_LIGNE];
    /* GET_DESCRIPTOR : requête standard (bits 6..5 à 0), entrante, bRequest = 6 (table 9-4). */
    int get_descripteur = (setup[0] & 0x80) && (setup[0] & 0x60) == 0 && setup[1] == 6;

    if (get_descripteur && setup[3] == 1 && lg >= 18)
        i_serie = donnees[16]; /* iSerialNumber, table 9-8 */
    if (get_descripteur && setup[3] == 3 && setup[2] != 0 && setup[2] == i_serie) {
        /* Le numéro de série identifie l'appareil de David : il ne doit jamais
         * finir dans une trace (CLAUDE.md). Notre code ne le demande pas, mais
         * la trace le masquerait quand même. */
        snprintf(buf, sizeof buf, "%zu o  (num\xC3\xA9ro de s\xC3\xA9rie masqu\xC3\xA9)", lg);
        ligne("CTRL-IN", buf);
        return;
    }
    hexa(hx, sizeof hx, donnees, lg, OCTETS_MAX);
    snprintf(buf, sizeof buf, "%zu o  %s", lg, hx);
    ligne("CTRL-IN", buf);
    if (get_descripteur) {
        decrire_descripteurs(donnees, lg, setup[2]);
    } else if (setup[1] == 0xFE && (setup[0] & 0x60) == 0x20 && lg >= 1) {
        snprintf(buf, sizeof buf, "plus haut LUN = %u", donnees[0]); /* BOT §3.2 */
        suite(buf);
    }
}

void trace_ctrl_out(const uint8_t *donnees, size_t lg)
{
    char hx[LG_LIGNE], buf[LG_LIGNE];
    hexa(hx, sizeof hx, donnees, lg, OCTETS_MAX);
    snprintf(buf, sizeof buf, "%zu o  %s", lg, hx);
    ligne("CTRL-OUT", buf);
}

void trace_cbw(const uint8_t cbw[31])
{
    char hx[64], op[64], buf[LG_LIGNE];
    /* CBW, BOT §5.1 : dCBWSignature 'USBC' (0x43425355), dCBWTag, dCBWDataTransferLength,
     * bmCBWFlags (bit 7 = sens IN), bCBWLUN, bCBWCBLength, CBWCB[16]. Petit-boutiste. */
    if (le32(cbw) != 0x43425355) {
        trace_data_out(cbw, 31);
        return;
    }
    cbw_tag = le32(cbw + 4);
    cbw_lg_donnees = le32(cbw + 8);
    cbw_lg_cdb = cbw[14] > 16 ? 16 : cbw[14];
    memcpy(cbw_cdb, cbw + 15, 16);
    cbw_en_cours = 1;
    hexa(hx, sizeof hx, cbw_cdb, cbw_lg_cdb, -1);
    nom_opcode(op, sizeof op, cbw_lg_cdb ? cbw_cdb[0] : -1);
    snprintf(buf, sizeof buf, "tag=0x%08X lun=%u %s %u o  CDB[%zu]=%s  %s", cbw_tag, cbw[13],
             (cbw[12] & 0x80) ? "IN" : "OUT", le32(cbw + 8), cbw_lg_cdb, hx, op);
    ligne("CBW", buf);
    if (cbw_lg_cdb && (cbw_cdb[0] == 0xC5 || cbw_cdb[0] == 0xC3))
        decrire_cdb_vendeur();
}

/* Vrai si la réponse à la commande en cours peut contenir le numéro de série
 * (CLAUDE.md) : réponses 0xC5 de 128 et 165 octets, page VPD 0x80 (« Unit Serial
 * Number », SPC-4) d'un INQUIRY. Leurs octets ne vont jamais dans une trace. */
static int contient_serie(size_t lg)
{
    if (!cbw_en_cours || cbw_lg_cdb == 0)
        return 0;
    if (cbw_cdb[0] == 0xC5 && (lg == 128 || lg == 165 || cbw_lg_donnees == 128 || cbw_lg_donnees == 165))
        return 1;
    return cbw_cdb[0] == 0x12 && cbw_lg_cdb > 2 && (cbw_cdb[1] & 1) && cbw_cdb[2] == 0x80;
}

void trace_data_in(const uint8_t *donnees, size_t lg)
{
    char hx[LG_LIGNE], buf[LG_LIGNE];
    if (lg == 0)
        return; /* paquet vide : l'analyseur n'en fait pas de ligne non plus */
    if (contient_serie(lg)) {
        snprintf(buf, sizeof buf, "%zu o  (num\xC3\xA9ro de s\xC3\xA9rie masqu\xC3\xA9)", lg);
        ligne("DATA-IN", buf);
        return;
    }
    hexa(hx, sizeof hx, donnees, lg, OCTETS_MAX);
    snprintf(buf, sizeof buf, "%zu o  %s", lg, hx);
    ligne("DATA-IN", buf);
    if (cbw_en_cours) {
        decrire_reponse_scsi(donnees, lg);
        decrire_reponse_vendeur(donnees, lg);
    }
}

void trace_data_out(const uint8_t *donnees, size_t lg)
{
    char hx[LG_LIGNE], buf[LG_LIGNE];
    int depot = depot_en_cours();
    if (depot && lg > 10 && donnees[0] == 0x2A && donnees[2] == 0x85) {
        /* SEND 0x85 : Capture Tool y met le numéro de série (CLAUDE.md). Notre
         * code ne l'envoie pas (tunnel.c le refuserait), mais la trace le masque. */
        hexa(hx, sizeof hx, donnees, 10, -1);
        snprintf(buf, sizeof buf, "%zu o  %s + %zu o (numéro de série masqué)", lg, hx, lg - 10);
        ligne("DATA-OUT", buf);
    } else {
        hexa(hx, sizeof hx, donnees, lg, OCTETS_MAX);
        snprintf(buf, sizeof buf, "%zu o  %s", lg, hx);
        ligne("DATA-OUT", buf);
    }
    if (depot)
        decrire_depot(donnees, lg);
}

void trace_csw(const uint8_t csw[13])
{
    static const char *statuts[] = {"r\xC3\xA9ussite", "\xC3\xA9" "chec", "erreur de phase"}; /* BOT §5.2, table 5.3 */
    char buf[LG_LIGNE], alerte[64] = "";
    /* CSW, BOT §5.2 : dCSWSignature 'USBS' (0x53425355), dCSWTag, dCSWDataResidue, bCSWStatus. */
    if (le32(csw) != 0x53425355) {
        trace_data_in(csw, 13);
        return;
    }
    uint32_t tag = le32(csw + 4);
    uint8_t statut = csw[12];
    if (!cbw_en_cours || tag != cbw_tag)
        snprintf(alerte, sizeof alerte, "  !! tag inattendu (CBW 0x%08X)", cbw_en_cours ? cbw_tag : 0u);
    cbw_en_cours = 0;
    snprintf(buf, sizeof buf, "tag=0x%08X statut=%u (%s) r\xC3\xA9sidu=%u%s", tag, statut,
             statut < 3 ? statuts[statut] : "?", le32(csw + 8), alerte);
    ligne("CSW", buf);
}

void trace_urb(const char *fonction, uint8_t endpoint)
{
    char buf[128];
    snprintf(buf, sizeof buf, "%s ep=0x%02X", fonction, endpoint); /* comme l'analyseur */
    ligne("URB", buf);
}

void trace_erreur(uint8_t endpoint, const char *type, unsigned long code_win32)
{
    /* L'analyseur affiche le code USBD_STATUS vu par USBPcap ; WinUSB ne nous
     * rend qu'un code Win32. Les plus probables sont nommés, les autres en clair. */
    const char *nom;
    char buf[256];
    switch (code_win32) {
    case ERROR_GEN_FAILURE: nom = "ERROR_GEN_FAILURE (STALL probable)"; break;
    case ERROR_SEM_TIMEOUT: nom = "ERROR_SEM_TIMEOUT"; break;
    case ERROR_INVALID_PARAMETER: nom = "ERROR_INVALID_PARAMETER"; break;
    case ERROR_OPERATION_ABORTED: nom = "ERROR_OPERATION_ABORTED"; break;
    case ERROR_BAD_COMMAND: nom = "ERROR_BAD_COMMAND"; break;
    case ERROR_DEVICE_NOT_CONNECTED: nom = "ERROR_DEVICE_NOT_CONNECTED"; break;
    default: nom = "?"; break;
    }
    snprintf(buf, sizeof buf, "ep=0x%02X %s Win32=%lu %s", endpoint, type, code_win32, nom);
    ligne("ERREUR", buf);
}
