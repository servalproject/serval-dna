#ifndef crypto_onetimeauth_poly1305_H
#define crypto_onetimeauth_poly1305_H

#define crypto_onetimeauth_poly1305_ref_BYTES 16
#define crypto_onetimeauth_poly1305_ref_KEYBYTES 32
#ifdef __cplusplus
#include <string>
extern std::string crypto_onetimeauth_poly1305_ref(const std::string &,const std::string &);
extern void crypto_onetimeauth_poly1305_ref_verify(const std::string &,const std::string &,const std::string &);
extern "C" {
#endif
extern int crypto_onetimeauth_poly1305_ref(unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_onetimeauth_poly1305_ref_verify(const unsigned char *,const unsigned char *,unsigned long long,const unsigned char *);
#ifdef __cplusplus
}
#endif

#define crypto_onetimeauth_poly1305 crypto_onetimeauth_poly1305_ref
/* POTATO crypto_onetimeauth_poly1305_ref crypto_onetimeauth_poly1305_ref crypto_onetimeauth_poly1305 */
#define crypto_onetimeauth_poly1305_verify crypto_onetimeauth_poly1305_ref_verify
/* POTATO crypto_onetimeauth_poly1305_ref_verify crypto_onetimeauth_poly1305_ref crypto_onetimeauth_poly1305 */
#define crypto_onetimeauth_poly1305_BYTES crypto_onetimeauth_poly1305_ref_BYTES
/* POTATO crypto_onetimeauth_poly1305_ref_BYTES crypto_onetimeauth_poly1305_ref crypto_onetimeauth_poly1305 */
#define crypto_onetimeauth_poly1305_KEYBYTES crypto_onetimeauth_poly1305_ref_KEYBYTES
/* POTATO crypto_onetimeauth_poly1305_ref_KEYBYTES crypto_onetimeauth_poly1305_ref crypto_onetimeauth_poly1305 */
#define crypto_onetimeauth_poly1305_IMPLEMENTATION "crypto_onetimeauth/poly1305/ref"
#ifndef crypto_onetimeauth_poly1305_ref_VERSION
#define crypto_onetimeauth_poly1305_ref_VERSION "-"
#endif
#define crypto_onetimeauth_poly1305_VERSION crypto_onetimeauth_poly1305_ref_VERSION

#endif
