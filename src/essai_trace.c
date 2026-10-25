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

#include "trace.h"

/* Un transfert de contrôle de la capture : paquet SETUP, puis réponse éventuelle. */
struct controle {
    uint8_t setup[8];
    uint8_t reponse[64];
    size_t lg;
};

/* Copiés des trames de 1b (premier nombre du commentaire : trame du SETUP,
 * second : trame de la réponse). */
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
    trace_fermer();
    return 0;
}
