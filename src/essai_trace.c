/*
 * essai_trace.c : banc d'essai du module de trace, sans scanner.
 *
 * On rejoue dans trace.c les octets exacts de l'énumération capturée dans
 * 1b-enumeration.pcap (adresse 15, trames 19191 à 19236), puis
 * banc/compare_traces.py confronte notre trace à celle de l'analyseur Python.
 * Si les deux concordent, notre décodage en C dit la même chose que l'analyseur,
 * qui a lui-même été contre-vérifié par tshark à l'étape 1d.
 *
 * Pourquoi un programme d'essai séparé plutôt qu'une option de ds720d.exe :
 * le programme qui parle au scanner reste court, et cet essai tourne sans matériel.
 *
 * Le numéro de série n'apparaît pas ici : pour les trames 19211 et 19213, on
 * envoie un faux numéro (« TEST »), que la trace doit de toute façon masquer.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <string.h>

#include "trace.h"

/* Un transfert de contrôle de la capture : paquet SETUP, puis réponse éventuelle. */
struct controle {
    uint8_t setup[8];
    uint8_t reponse[64];
    size_t lg;
};

/* Copiés des trames de 1b (premier nombre du commentaire : trame du SETUP,
 * second : trame de la réponse), sauf la chaîne du numéro de série, remplacée
 * par un faux plus court (le SETUP de 19212 demande alors 10 octets au lieu de
 * 34) ; ces lignes-là sont exclues de la comparaison. */
static const struct controle controles[] = {
    /* 19191 / 19194 : GET_DESCRIPTOR DEVICE, 18 octets */
    {{0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00},
     {0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0xf9, 0x04, 0xe2, 0x60, 0x00, 0x01, 0x01,
      0x02, 0x03, 0x01},
     18},
    /* 19195 / 19196 : GET_DESCRIPTOR CONFIGURATION, 9 octets pour lire wTotalLength */
    {{0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x09, 0x00},
     {0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x7d},
     9},
    /* 19197 / 19199 : GET_DESCRIPTOR CONFIGURATION, les 32 octets */
    {{0x80, 0x06, 0x00, 0x02, 0x00, 0x00, 0x20, 0x00},
     {0x09, 0x02, 0x20, 0x00, 0x01, 0x01, 0x00, 0x80, 0x7d, 0x09, 0x04, 0x00, 0x00, 0x02, 0x08,
      0x06, 0x50, 0x00, 0x07, 0x05, 0x81, 0x02, 0x00, 0x02, 0x00, 0x07, 0x05, 0x02, 0x02, 0x00,
      0x02, 0x00},
     32},
    /* 19200 / 19204 : GET_DESCRIPTOR STRING 0, 2 octets (bLength seul) */
    {{0x80, 0x06, 0x00, 0x03, 0x00, 0x00, 0x02, 0x00}, {0x04, 0x03}, 2},
    /* 19205 / 19206 : GET_DESCRIPTOR STRING 0, 4 octets : langue 0x0409 */
    {{0x80, 0x06, 0x00, 0x03, 0x00, 0x00, 0x04, 0x00}, {0x04, 0x03, 0x09, 0x04}, 4},
    /* 19207 / 19211 et 19212 / 19213 : chaîne du numéro de série (iSerial = 3),
     * remplacée par un faux « TEST » ; la trace doit la masquer. */
    {{0x80, 0x06, 0x03, 0x03, 0x09, 0x04, 0x02, 0x00}, {0x0a, 0x03}, 2},
    {{0x80, 0x06, 0x03, 0x03, 0x09, 0x04, 0x0a, 0x00},
     {0x0a, 0x03, 'T', 0, 'E', 0, 'S', 0, 'T', 0},
     10},
    /* 19214 : SET_CONFIGURATION 1, sans données */
    {{0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, {0}, 0},
    /* 19218 : SET_INTERFACE 0/0, sans données */
    {{0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, {0}, 0},
    /* 19223 / 19224 : GET_MAX_LUN (BOT §3.2) : plus haut LUN = 0 */
    {{0xa1, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}, {0x00}, 1},
};

/* 19228 et 19234 : réponse INQUIRY de 36 octets, identique les deux fois. */
static const uint8_t inquiry[36] = {
    0x00, 0x80, 0x05, 0x02, 0x20, 0x00, 0x00, 0x00, 'B', 'r', 'o', 't', 'h', 'e', 'r', ' ',
    'D',  'S',  '-',  '7',  '2',  '0',  'D',  ' ',  ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    '0',  '.',  '2',  '7',
};

/* Un INQUIRY complet : CBW, données, CSW, avec le tag de la capture. */
static void rejouer_inquiry(uint32_t tag)
{
    uint8_t cbw[31] = {
        0x55, 0x53, 0x42, 0x43,                         /* 'USBC' */
        (uint8_t)tag, (uint8_t)(tag >> 8), (uint8_t)(tag >> 16), (uint8_t)(tag >> 24),
        0x24, 0x00, 0x00, 0x00,                         /* 36 octets attendus */
        0x80, 0x00, 0x06,                               /* IN, LUN 0, CDB de 6 octets */
        0x12, 0x00, 0x00, 0x00, 0x24, 0x00,             /* INQUIRY, allocation 36 */
    };
    uint8_t csw[13] = {
        0x55, 0x53, 0x42, 0x53,                         /* 'USBS' */
        (uint8_t)tag, (uint8_t)(tag >> 8), (uint8_t)(tag >> 16), (uint8_t)(tag >> 24),
        0x00, 0x00, 0x00, 0x00, 0x00,                   /* résidu 0, statut 0 */
    };
    trace_cbw(cbw);
    trace_data_in(inquiry, sizeof inquiry);
    trace_csw(csw);
}

/* ------------------------------------------------------------------------- */
/* Protocole vendeur (étape 3c) : échanges 0xC5 et 0xC3 copiés de 1b et de 2a, */
/* pour confronter le décodage de trace.c à la section 5 de l'analyseur.      */
/* ------------------------------------------------------------------------- */

/* Un échange : CBW de 16 octets de CDB, données entrantes éventuelles, CSW
 * éventuel. Le tag est quelconque : la comparaison se fait avec --sans-tags. */
static void rejouer_vendeur(const uint8_t cdb[16], uint32_t lg, const uint8_t *reponse, size_t lg_reponse,
                            int avec_csw)
{
    static uint32_t tag = 0x3C000000;
    uint8_t cbw[31] = {
        0x55, 0x53, 0x42, 0x43,                         /* 'USBC' */
        (uint8_t)tag, (uint8_t)(tag >> 8), (uint8_t)(tag >> 16), (uint8_t)(tag >> 24),
        (uint8_t)lg, (uint8_t)(lg >> 8), (uint8_t)(lg >> 16), (uint8_t)(lg >> 24),
        0x80, 0x00, 0x10,                               /* IN, LUN 0, CDB de 16 octets */
    };
    uint8_t csw[13] = {
        0x55, 0x53, 0x42, 0x53,                         /* 'USBS' */
        (uint8_t)tag, (uint8_t)(tag >> 8), (uint8_t)(tag >> 16), (uint8_t)(tag >> 24),
        0x00, 0x00, 0x00, 0x00, 0x00,                   /* résidu 0, statut 0 */
    };
    memcpy(cbw + 15, cdb, 16);
    trace_cbw(cbw);
    if (lg_reponse)
        trace_data_in(reponse, lg_reponse);
    if (avec_csw)
        trace_csw(csw);
    tag++;
}

/* Lecture par le tunnel 0xC5 : CDB c5 07, longueur gros-boutiste, sélecteur. */
static void rejouer_c5(uint8_t s0, uint8_t s1, uint8_t s2, const uint8_t *reponse, uint32_t lg)
{
    uint8_t cdb[16] = {0xC5, 0x07, 0, 0, 0, 0, (uint8_t)(lg >> 24), (uint8_t)(lg >> 16), (uint8_t)(lg >> 8),
                       (uint8_t)lg, s0, s1, s2};
    rejouer_vendeur(cdb, lg, reponse, lg, 1);
}

/* Réponses de 1b et 2a. Les sondages ff 03 rendent 0 dans l'octet 8, les
 * sondages ff 04 à ff 06 y rendent 1 (protocole.md §2). */
static const uint8_t nova[4] = {'N', 'O', 'V', 'A'};
static const uint8_t sondage_0[16] = {0x10, 0, 0, 0, 0x01, 0, 0, 0, 0x00};
static const uint8_t sondage_1[16] = {0x10, 0, 0, 0, 0x01, 0, 0, 0, 0x01};
static const uint8_t entete_2[2] = {0x10, 0x00};
static const uint8_t vid[2] = {0x04, 0xf9}, pid[2] = {0x60, 0xe2};
static const uint8_t entete_4[4] = {0x10, 0, 0, 0}, statut_0[4] = {0};
/* 2a trame 52310 : bloc prêt, 2592 × 240, adresse 0x0059AA00 ; trame 120209 : fin de page. */
static const uint8_t bloc_pret[24] = {0x01, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0,
                                      0x20, 0x0a, 0, 0, 0xf0, 0, 0, 0, 0x00, 0xaa, 0x59, 0x00};
static const uint8_t fin_de_page[24] = {0x03, 0, 0, 0, 0x01};

static void rejouer_protocole_vendeur(void)
{
    trace_note("essai : prise de contact Brother, 1b trames 20841 à 20961");
    rejouer_c5(0xff, 0x02, 0x00, nova, 4);         /* 20841 */
    rejouer_c5(0xff, 0x02, 0x00, nova, 4);         /* 20848 */
    rejouer_c5(0xff, 0x04, 0x00, sondage_1, 16);   /* 20854 */
    rejouer_c5(0xff, 0x03, 0x00, sondage_0, 16);   /* 20860 */
    rejouer_c5(0xff, 0x03, 0x00, sondage_0, 16);   /* 20866 */
    rejouer_c5(0xff, 0x05, 0x00, sondage_1, 16);   /* 20872 */
    rejouer_c5(0x02, 0x01, 0x03, entete_2, 2);     /* 20880 */
    rejouer_c5(0xff, 0x04, 0x00, sondage_1, 16);   /* 20886 */
    rejouer_c5(0x02, 0x02, 0x03, vid, 2);          /* 20893 */
    rejouer_c5(0xff, 0x04, 0x00, sondage_1, 16);   /* 20899 */
    rejouer_c5(0xff, 0x06, 0x00, sondage_1, 16);   /* 20905 */
    rejouer_c5(0xff, 0x04, 0x00, sondage_1, 16);   /* 20911 */
    rejouer_c5(0xff, 0x03, 0x00, sondage_0, 16);   /* 20917 */
    rejouer_c5(0xff, 0x03, 0x00, sondage_0, 16);   /* 20923 */
    rejouer_c5(0xff, 0x05, 0x00, sondage_1, 16);   /* 20929 */
    rejouer_c5(0x02, 0x01, 0x04, entete_2, 2);     /* 20935 */
    rejouer_c5(0xff, 0x04, 0x00, sondage_1, 16);   /* 20941 */
    rejouer_c5(0x02, 0x02, 0x04, pid, 2);          /* 20950 */
    rejouer_c5(0xff, 0x04, 0x00, sondage_1, 16);   /* 20956 */

    trace_note("essai : statut d'une commande déposée, 2a trames 905 à 922");
    rejouer_c5(0x02, 0x01, 0x01, entete_4, 4);     /* 905 */
    rejouer_c5(0xff, 0x04, 0x00, sondage_1, 16);   /* 911 */
    rejouer_c5(0x02, 0x02, 0x01, statut_0, 4);     /* 917 */

    trace_note("essai : bloc d'image prêt et première lecture 0xC3, 2a trames 52307 à 52312 et 52325");
    rejouer_c5(0x02, 0x02, 0x02, bloc_pret, 24);   /* 52307 */
    /* 52325 : CBW seul. Les 65 536 octets de données sont un morceau d'image de
     * document : ils restent hors du dépôt, et la trame 52330 hors de la comparaison. */
    static const uint8_t c3[16] = {0xC3, 0x07, 0x00, 0x59, 0xaa, 0x00, 0x00, 0x01, 0x00, 0x00};
    rejouer_vendeur(c3, 65536, NULL, 0, 0);

    trace_note("essai : fin de page, 2a trames 120206 à 120211");
    rejouer_c5(0x02, 0x02, 0x02, fin_de_page, 24); /* 120206 */
}

int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8); /* la trace est en UTF-8 (accents, « … ») */
    if (trace_ouvrir(argc > 1 ? argv[1] : NULL) != 0) {
        fprintf(stderr, "impossible d'ouvrir %s\n", argv[1]);
        return 1;
    }
    trace_note("essai : énumération rejouée depuis 1b-enumeration.pcap, trames 19191 à 19236");
    for (size_t i = 0; i < sizeof controles / sizeof controles[0]; i++) {
        trace_setup(controles[i].setup);
        if (controles[i].lg)
            trace_ctrl_in(controles[i].setup, controles[i].reponse, controles[i].lg);
    }
    rejouer_inquiry(0xA41D25B0); /* trames 19225 à 19230 */
    rejouer_inquiry(0x961C5290); /* trames 19231 à 19236 */
    rejouer_protocole_vendeur();
    trace_fermer();
    return 0;
}
