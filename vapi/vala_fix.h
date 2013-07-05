#ifndef VALA_FIX_H
#define VALA_FIX_H

/*
 * This file exists as a workaround for current ValaC (0.20.1) which has issues
 * with cname containing spaces.
 */

//#define struct_ccn_keystore struct ccn_keystore
typedef struct ccn_keystore ccn_keystore_t;

#endif /* VALA_FIX_H */
