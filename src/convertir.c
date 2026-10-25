/*
 * convertir.c : image brute du DS-720D (ds720d scan) vers PGM ou PNG.
 *
 * Usage :
 *   convertir BRUT --pgm SORTIE.pgm
 *   convertir BRUT --png SORTIE.png [--couleur] [--ppp-y 600]
 *
 * Pourquoi un programme à part plutôt qu'une option de ds720d.exe : la
 * conversion ne parle pas au scanner, elle se rejoue autant qu'on veut sur une
 * image déjà lue (ou extraite d'une capture par banc/extrait_image.py), et
 * ds720d.exe reste centré sur le protocole. Les fichiers produits contiennent
 * l'image d'un document : ils restent hors du dépôt (CLAUDE.md).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "image.h"

static void usage(void)
{
    fprintf(stderr, "usage : convertir BRUT --pgm SORTIE.pgm\n"
                    "        convertir BRUT --png SORTIE.png [--couleur] [--ppp-y 600]\n");
}

int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8);
    const char *brut = NULL, *pgm = NULL, *png = NULL;
    int couleur = 0;
    unsigned ppp_y = 300; /* résolution Y de la fenêtre : 300, ou 600 (1e-gris-600-recto) */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pgm") == 0 && i + 1 < argc)
            pgm = argv[++i];
        else if (strcmp(argv[i], "--png") == 0 && i + 1 < argc)
            png = argv[++i];
        else if (strcmp(argv[i], "--couleur") == 0)
            couleur = 1;
        else if (strcmp(argv[i], "--ppp-y") == 0 && i + 1 < argc)
            ppp_y = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!brut)
            brut = argv[i];
        else {
            usage();
            return 2;
        }
    }
    if (!brut || (!pgm == !png) || (couleur && !png) || (ppp_y != 300 && ppp_y != 600)) {
        usage();
        return 2;
    }

    /* Lecture du fichier brut en entier : une page fait au plus quelques dizaines
     * de mégaoctets (40 Mo pour l'A4 à 600 dpi de 1e-gris-600-recto). */
    FILE *f;
    if (fopen_s(&f, brut, "rb") != 0) {
        fprintf(stderr, "impossible d'ouvrir %s\n", brut);
        return 1;
    }
    _fseeki64(f, 0, SEEK_END);
    long long taille = _ftelli64(f);
    _fseeki64(f, 0, SEEK_SET);
    if (taille <= 0 || taille % IMAGE_OCTETS_LIGNE || taille > (1ll << 30)) {
        fprintf(stderr, "%s : %lld octets, pas un nombre entier de lignes de %u octets\n", brut, taille,
                IMAGE_OCTETS_LIGNE);
        fclose(f);
        return 1;
    }
    uint8_t *octets = malloc((size_t)taille);
    if (!octets || fread(octets, 1, (size_t)taille, f) != (size_t)taille) {
        fprintf(stderr, "lecture de %s impossible\n", brut);
        fclose(f);
        free(octets);
        return 1;
    }
    fclose(f);
    size_t lignes = (size_t)(taille / IMAGE_OCTETS_LIGNE);

    int r = pgm ? image_pgm(pgm, octets, lignes) : image_png(png, octets, lignes, couleur, ppp_y);
    free(octets);
    if (r != 0) {
        fprintf(stderr, "écriture de %s impossible (existe-t-il déjà ?)\n", pgm ? pgm : png);
        return 1;
    }
    printf("%s : %u × %zu, %s\n", pgm ? pgm : png, IMAGE_LARGEUR, lignes,
           pgm ? "gris (plan vert)" : couleur ? "couleur" : "gris (plan vert)");
    return 0;
}
