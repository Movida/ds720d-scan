/*
 * rendu.h : de l'image brute du DS-720D à une page lisible (étape 4d).
 *
 * Le scanner rend toujours des lignes de 3 plans de 2 592 points en 300 ppp
 * horizontaux, sombres, avec des marges, et le verso en miroir
 * (docs/protocole.md §5 et §6). Ce module en tire la page que l'on regarde,
 * en suivant ce que fait le pilote Brother, mesuré sur ses BMP :
 *   - recadrage : 2 548 points (2 550 à 600 dpi) et les premières lignes sautées ;
 *   - verso : retourné de gauche à droite, 135 lignes de retard rattrapées ;
 *   - courbe de tons du gris (docs/courbe-gris.txt) ;
 *   - 600 dpi : largeur doublée par interpolation linéaire.
 */
#ifndef DS720D_RENDU_H
#define DS720D_RENDU_H

#include <stddef.h>
#include <stdint.h>

#include "image.h"

struct rendu_options {
    unsigned ppp_y; /* résolution verticale de la fenêtre : 300 ou 600 */
    int verso;      /* 1 : face arrière d'un scan recto-verso */
    int couleur;    /* 1 : trois plans ; 0 : gris, c'est-à-dire le plan vert */
    int brut;       /* 1 : aucun rendu, les points tels que le scanner les rend */
};

/* Remplit im (points alloués par malloc, à libérer par l'appelant) à partir de
 * lignes lignes brutes. Renvoie 0, ou -1 si la page est trop courte ou si la
 * mémoire manque. */
int rendu_page(const uint8_t *brut, size_t lignes, const struct rendu_options *o, struct image *im);

/* Courbe de tons du gris, exposée pour le banc d'essai. */
extern const uint8_t rendu_courbe_gris[256];

#endif
