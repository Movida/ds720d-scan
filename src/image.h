/*
 * image.h : écriture de l'image brute du DS-720D en PGM et en PNG, à la main.
 *
 * L'image brute est celle que rendent les lectures 0xC3 (docs/protocole.md §5) :
 * des lignes de 3 plans de 2 592 points, rouge, vert, bleu, 8 bits. Ce module
 * n'en change pas les valeurs : pas de recadrage, pas de courbe de tons.
 */
#ifndef DS720D_IMAGE_H
#define DS720D_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#define IMAGE_LARGEUR 2592u                    /* points par ligne et par plan */
#define IMAGE_OCTETS_LIGNE (3u * IMAGE_LARGEUR) /* une ligne : rouge, vert, bleu */

/* PGM binaire (« P5 », spécification Netpbm) en 8 bits, plan vert seul : c'est
 * lui que suit le gris du pilote Brother (protocole.md §5). */
int image_pgm(const char *chemin, const uint8_t *brut, size_t lignes);

/* PNG (ISO/IEC 15948, « PNG Specification, Second Edition ») 8 bits, en gris
 * (plan vert) ou en couleur (RVB), données zlib en blocs deflate « stockés »,
 * sans compression. Renvoie 0 si tout va bien. */
int image_png(const char *chemin, const uint8_t *brut, size_t lignes, int couleur);

/* CRC-32 de PNG (annexe D) et Adler-32 de zlib (RFC 1950 §8), exposés pour le
 * banc d'essai : valeurs de référence connues à vérifier. */
uint32_t image_crc32(uint32_t crc, const uint8_t *o, size_t lg);
uint32_t image_adler32(uint32_t adler, const uint8_t *o, size_t lg);

#endif
