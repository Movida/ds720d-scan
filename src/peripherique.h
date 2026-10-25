/*
 * peripherique.h : accès au scanner par WinUSB.
 *
 * Ce module trouve le scanner, l'ouvre et lui envoie des transferts de contrôle
 * et des transferts bulk. Il ne connaît ni les descripteurs, ni le transport
 * Bulk-Only, ni SCSI : ces octets-là sont construits par l'appelant, à la main.
 * Chaque transfert est tracé (trace.h) au moment où il part ou arrive.
 */
#ifndef DS720D_PERIPHERIQUE_H
#define DS720D_PERIPHERIQUE_H

#include <stddef.h>
#include <stdint.h>

/* Identifiants du DS-720D, lus dans son descripteur DEVICE (trame 19194 de 1b). */
#define DS720D_VID 0x04F9
#define DS720D_PID 0x60E2

/* Trouve le scanner, vérifie qu'il est bien sous WinUSB, l'ouvre.
 * Renvoie 0 si tout va bien ; sinon explique le problème sur stderr. */
int periph_ouvrir(void);
void periph_fermer(void);

/* Transfert de contrôle sur l'endpoint 0 (USB 2.0 §8.5.3 et §9.3).
 * setup : les 8 octets du paquet SETUP, construits par l'appelant (table 9-2).
 * donnees : tampon de wLength octets (sens donné par le bit 7 de bmRequestType).
 * Renvoie le nombre d'octets transférés, ou -1 en cas d'échec. */
long periph_controle(const uint8_t setup[8], uint8_t *donnees);

/* Transferts bulk (USB 2.0 §5.8) sur l'endpoint donné. Ces deux fonctions ne
 * tracent que les échecs : le sens des octets (CBW, données, CSW) n'est connu
 * que de l'appelant, qui les trace lui-même. Renvoient le nombre d'octets
 * transférés, ou -1 en cas d'échec (code Win32 dans *erreur si non NULL). */
long periph_bulk_ecrire(uint8_t endpoint, const uint8_t *donnees, size_t lg, unsigned long *erreur);
long periph_bulk_lire(uint8_t endpoint, uint8_t *donnees, size_t lg, unsigned long *erreur);

/* Débloque un endpoint bulk après un STALL : CLEAR_FEATURE(ENDPOINT_HALT) côté
 * appareil (USB 2.0 §9.4.1, §9.4.5) et remise à DATA0 du basculement de données
 * côté hôte (§8.6.4). Renvoie 0 si tout va bien, -1 sinon. */
int periph_debloquer(uint8_t endpoint);

#endif
