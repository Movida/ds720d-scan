/*
 * essai_refus.c : la barrière du pilote noyau, vérifiée sur le vrai pilote
 * (étape 6e). À lancer dans la VM, le scanner tenu par ds720d.sys.
 *
 * Deux requêtes absentes de la liste (src/permis.c), choisies inoffensives au
 * cas où la barrière laisserait passer à tort :
 *   - TEST UNIT READY (SPC, opcode 0x00), que Windows envoie au faux disque
 *     sous USBSTOR (5d) mais que notre code n'envoie jamais : une simple
 *     question « es-tu prêt ? », sans données ;
 *   - GET_DESCRIPTOR STRING 2 (USB 2.0 §9.4.3), le nom du produit, en lecture,
 *     jamais demandé par notre code (le numéro de série, STRING 3, est exclu
 *     même ici).
 * Les deux doivent échouer avec ERROR_ACCESS_DENIED, et une capture USBPcap
 * prise pendant l'essai ne doit rien montrer : le pilote refuse avant tout
 * envoi. Lié à client_noyau.c et trace.c, comme ds720dk.exe.
 * Code de sortie : 0 si les deux requêtes sont refusées.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>

#include "bot.h"
#include "peripherique.h"
#include "trace.h"

int main(void)
{
    static const uint8_t tur[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const uint8_t string2[8] = {0x80, 0x06, 0x02, 0x03, 0x09, 0x04, 0xff, 0x00};
    uint8_t tampon[255];
    struct bot_resultat r;
    int refus = 0;

    SetConsoleOutputCP(CP_UTF8);
    if (trace_ouvrir(NULL) != 0 || periph_ouvrir() != 0)
        return 2;

    if (bot_commande_in(0, tur, sizeof tur, NULL, 0, &r) != 0 && GetLastError() == ERROR_ACCESS_DENIED) {
        printf("TEST UNIT READY : refusé par le pilote, comme attendu\n");
        refus++;
    } else {
        printf("TEST UNIT READY : NON refusé (Win32=%lu)\n", GetLastError());
    }
    if (periph_controle(string2, tampon) < 0 && GetLastError() == ERROR_ACCESS_DENIED) {
        printf("GET_DESCRIPTOR STRING 2 : refusé par le pilote, comme attendu\n");
        refus++;
    } else {
        printf("GET_DESCRIPTOR STRING 2 : NON refusé (Win32=%lu)\n", GetLastError());
    }

    periph_fermer();
    trace_fermer();
    printf("%d refus sur 2\n", refus);
    return refus == 2 ? 0 : 1;
}
