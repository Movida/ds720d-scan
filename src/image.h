/*
 * image.h : écriture d'une image en PGM et en PNG, à la main.
 *
 * L'image arrive déjà prête (struct image) : soit les plans bruts tels que les
 * rendent les lectures 0xC3 (docs/protocole.md §5), soit la page rendue par
 * rendu.c (recadrage, courbe de tons, miroir du verso, largeur doublée à
 * 600 dpi). Ce module ne change aucune valeur : il ne fait que l'encodage.
 */
#ifndef DS720D_IMAGE_H
#define DS720D_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#define IMAGE_LARGEUR 2592u                    /* points bruts par ligne et par plan */
#define IMAGE_OCTETS_LIGNE (3u * IMAGE_LARGEUR) /* une ligne brute : rouge, vert, bleu */

/* Image à encoder : points ligne par ligne, de haut en bas, sans bourrage ;
 * 1 canal (gris) ou 3 entrelacés (rouge, vert, bleu). ppp_x et ppp_y vont dans le
 * chunk pHYs du PNG (300 ou 600). */
struct image {
    uint32_t largeur, hauteur, canaux;
    unsigned ppp_x, ppp_y;
    uint8_t *points;
};

/* PGM binaire (« P5 », spécification Netpbm) en 8 bits ; image en gris seulement. */
int image_pgm(const char *chemin, const struct image *im);

/* PNG (ISO/IEC 15948, « PNG Specification, Second Edition ») 8 bits, en gris ou
 * en RVB, données zlib en blocs deflate « stockés », sans compression.
 * Renvoie 0 si tout va bien. */
int image_png(const char *chemin, const struct image *im);

/* CRC-32 de PNG (annexe D) et Adler-32 de zlib (RFC 1950 §8), exposés pour le
 * banc d'essai : valeurs de référence connues à vérifier. */
uint32_t image_crc32(uint32_t crc, const uint8_t *o, size_t lg);
uint32_t image_adler32(uint32_t adler, const uint8_t *o, size_t lg);

#endif
