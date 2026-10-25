/*
 * usb.h : couche URB du pilote (étape 6d, docs/pilote.md).
 *
 * Tout ce que le pilote envoie au scanner passe par ici, sous forme d'URB
 * (USB Request Block, usb.h du WDK) remplis champ par champ et confiés à la
 * pile USB de Windows par IOCTL_INTERNAL_USB_SUBMIT_URB, sans les objets USB
 * de KMDF (WDFUSBDEVICE, WDFUSBPIPE), qui construiraient les URB à notre place
 * (choix du § 2 de docs/pilote.md).
 *
 * Couche générique : elle ne connaît ni le DS-720D ni le Bulk-Only, et
 * servirait telle quelle à un autre appareil USB (docs/pilote.md, « Couches »).
 * Toutes ces fonctions s'appellent à PASSIVE_LEVEL : les envois sont
 * synchrones (docs/pilote.md, § 2, « Exécution »).
 */
#ifndef DS720D_USB_H
#define DS720D_USB_H

#include <ntddk.h>
#pragma warning(push)
#pragma warning(disable: 4324)
#include <wdf.h>
#pragma warning(pop)
#include <usb.h>
#include <usbdlib.h>

/* Étiquette de nos allocations dans le pool du noyau : « 720D » telle que
 * l'affichent !pool et Driver Verifier. Une constante de plusieurs caractères
 * range le dernier dans l'octet de poids faible, et la mémoire est
 * petit-boutiste : on l'écrit donc à l'envers. */
#define DS720D_ETIQUETTE 'D027'

/* Ce qu'il faut pour parler à un appareil USB par URB. */
typedef struct _USB_CIBLE {
    WDFIOTARGET cible;          /* le pilote d'en dessous (PDO du concentrateur) */
    USBD_HANDLE usbd;           /* notre inscription auprès de la pile USB */
    USBD_CONFIGURATION_HANDLE configuration; /* NULL tant qu'aucune n'est choisie */
} USB_CIBLE;

/* Ce que l'on retient d'un endpoint après la sélection de configuration. */
typedef struct _USB_PIPE {
    UCHAR adresse;              /* bEndpointAddress, bit 7 : sens entrant */
    USHORT taille_paquet;       /* wMaxPacketSize */
    USBD_PIPE_HANDLE poignee;   /* rendue par la pile, à mettre dans les URB */
} USB_PIPE;

/* Inscription auprès de la pile USB (USBD_CreateHandle) et cible d'E/S. */
NTSTATUS UsbOuvrir(WDFDEVICE appareil, USB_CIBLE *u);
/* Désinscription ; sans effet si UsbOuvrir n'a pas réussi. */
VOID UsbFermer(USB_CIBLE *u);

/* Transfert de contrôle sur le pipe par défaut : setup, les 8 octets du paquet
 * SETUP écrits par l'appelant (USB 2.0 §9.3) ; donnees, wLength octets en
 * mémoire non paginée. *transferes : octets effectivement passés. */
NTSTATUS UsbControle(USB_CIBLE *u, const UCHAR setup[8], PVOID donnees, ULONG *transferes);

/* Cherche, dans un descripteur de configuration complet de lg octets, la
 * première interface de la classe, sous-classe et protocole donnés, et ses
 * deux endpoints bulk, un dans chaque sens (USB 2.0 §9.6.3 à §9.6.6).
 * Renvoie l'interface, ou NULL. */
PUSB_INTERFACE_DESCRIPTOR UsbChercherInterface(PUSB_CONFIGURATION_DESCRIPTOR conf, ULONG lg, UCHAR classe,
                                               UCHAR sous_classe, UCHAR protocole);

/* Sélectionne la configuration conf avec la seule interface itf (URB
 * SELECT_CONFIGURATION : la pile envoie SET_CONFIGURATION, USB 2.0 §9.4.7) et
 * rend ses pipes bulk. */
NTSTATUS UsbChoisirConfiguration(USB_CIBLE *u, PUSB_CONFIGURATION_DESCRIPTOR conf, PUSB_INTERFACE_DESCRIPTOR itf,
                                 USB_PIPE *entrant, USB_PIPE *sortant);

/* Abandonne les transferts en cours sur un pipe (URB ABORT_PIPE), côté hôte :
 * rien ne part sur le bus. Sans effet sur un pipe jamais ouvert. */
NTSTATUS UsbAbandonner(USB_CIBLE *u, const USB_PIPE *pipe);

#endif
