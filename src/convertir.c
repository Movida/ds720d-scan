/*
 * convertir.c : image brute du DS-720D (ds720d scan) vers PGM ou PNG.
 *
 * Usage :
 *   convertir BRUT --pgm SORTIE.pgm [--verso] [--ppp-y 600] [--brut]
 *   convertir BRUT --png SORTIE.png [--couleur] [--verso] [--ppp-y 600] [--brut]
 *
 * Par défaut, la page est rendue comme par le pilote Brother (rendu.c : recadrage,
 * courbe de tons, verso redressé, largeur doublée à 600 dpi). --brut garde les
 * points tels que le scanner les rend, comme à l'étape 3f : c'est ce mode que
 * banc/verif_png.py compare au brut point par point.
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
#include "rendu.h"

static void usage(void)
{
    fprintf(stderr, "usage : convertir BRUT --pgm SORTIE.pgm [--verso] [--ppp-y 600] [--brut]\n"
                    "        convertir BRUT --png SORTIE.png [--couleur] [--verso] [--ppp-y 600] [--brut]\n");
}

int main(int argc, char **argv)
{
    SetConsoleOutputCP(CP_UTF8);
    const char *brut = NULL, *pgm = NULL, *png = NULL;
    struct rendu_options o = {300, 0, 0, 0}; /* ppp_y : 300, ou 600 (1e-gris-600-recto) */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--pgm") == 0 && i + 1 < argc)
            pgm = argv[++i];
        else if (strcmp(argv[i], "--png") == 0 && i + 1 < argc)
            png = argv[++i];
        else if (strcmp(argv[i], "--couleur") == 0)
            o.couleur = 1;
        else if (strcmp(argv[i], "--verso") == 0)
            o.verso = 1;
        else if (strcmp(argv[i], "--brut") == 0)
            o.brut = 1;
        else if (strcmp(argv[i], "--ppp-y") == 0 && i + 1 < argc)
            o.ppp_y = (unsigned)strtoul(argv[++i], NULL, 10);
        else if (!brut)
            brut = argv[i];
        else {
            usage();
            return 2;
        }
    }
    if (!brut || (!pgm == !png) || (o.couleur && !png) || (o.ppp_y != 300 && o.ppp_y != 600) ||
        (o.verso && (o.brut || o.ppp_y == 600))) { /* verso à 600 dpi : jamais capturé (rendu.c) */
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

    struct image im;
    int r = rendu_page(octets, lignes, &o, &im);
    free(octets);
    if (r != 0) {
        fprintf(stderr, "%s : page trop courte (%zu lignes) ou mémoire insuffisante\n", brut, lignes);
        return 1;
    }
    r = pgm ? image_pgm(pgm, &im) : image_png(png, &im);
    free(im.points);
    if (r != 0) {
        fprintf(stderr, "écriture de %s impossible (existe-t-il déjà ?)\n", pgm ? pgm : png);
        return 1;
    }
    printf("%s : %u × %u, %s, %s%s, %u × %u ppp\n", pgm ? pgm : png, im.largeur, im.hauteur,
           o.couleur ? "couleur" : "gris (plan vert)", o.brut ? "brut" : "rendu",
           o.verso ? " (verso)" : "", im.ppp_x, im.ppp_y);
    return 0;
}
