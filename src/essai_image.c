/*
 * essai_image.c : banc d'essai des sommes de contrôle de image.c, sans scanner.
 *
 * Valeurs de référence publiées :
 *   - CRC-32 de « 123456789 » : 0xCBF43926 (valeur de contrôle du CRC-32 de
 *     ISO 3309 / PNG, celle des catalogues de CRC) ;
 *   - Adler-32 de « Wikipedia » : 0x11E60398 (exemple de calcul détaillé de
 *     l'article Adler-32, cohérent avec RFC 1950 §8.2) ;
 *   - CRC-32 du chunk IEND vide : 0xAE426082, présent à la fin de tout PNG.
 * Le décodage d'un PNG complet se vérifie à part, par banc/verif_png.py.
 * Code de sortie : 0 si tout concorde.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>

#include "image.h"

static int verifier(const char *nom, uint32_t obtenu, uint32_t attendu)
{
    int bon = obtenu == attendu;
    printf("%s  %s : 0x%08X (attendu 0x%08X)\n", bon ? "OK   " : "ÉCHEC", nom, obtenu, attendu);
    return bon;
}

int main(void)
{
    SetConsoleOutputCP(CP_UTF8);
    const uint8_t chiffres[] = "123456789", wiki[] = "Wikipedia", iend[] = "IEND";
    int bons = 0;
    bons += verifier("CRC-32 de « 123456789 »", image_crc32(0, chiffres, 9), 0xCBF43926u);
    /* En deux morceaux : le CRC se reprend là où il s'est arrêté. */
    bons += verifier("CRC-32 en deux appels", image_crc32(image_crc32(0, chiffres, 4), chiffres + 4, 5), 0xCBF43926u);
    bons += verifier("CRC-32 de « IEND »", image_crc32(0, iend, 4), 0xAE426082u);
    bons += verifier("Adler-32 de « Wikipedia »", image_adler32(1, wiki, 9), 0x11E60398u);
    bons += verifier("Adler-32 en deux appels", image_adler32(image_adler32(1, wiki, 3), wiki + 3, 6), 0x11E60398u);
    printf("%d/5 cas conformes\n", bons);
    return bons == 5 ? 0 : 1;
}
