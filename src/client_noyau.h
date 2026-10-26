/*
 * client_noyau.h : ce que client_noyau.c offre en plus des fonctions de
 * peripherique.h et bot.h, pour les essais du pilote noyau seulement.
 */
#ifndef CLIENT_NOYAU_H
#define CLIENT_NOYAU_H

/*
 * Seconde ouverture du scanner, pendant que celle de periph_ouvrir est tenue
 * (étape 6i, essai_refus.c). Rend ERROR_SUCCESS si le pilote l'a acceptée (elle
 * est alors refermée aussitôt), sinon le code Win32 du refus :
 * ERROR_SHARING_VIOLATION attendu (Ds720dOuverture, noyau/ds720d.c).
 */
unsigned long periph_seconde_ouverture(void);

#endif
