/* 
 * File:   main.c
 * Author: kazim
 *
 * Created on March 7, 2014, 12:06 PM
 */

#include <stdio.h>
#include <stdlib.h>
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <confuse.h>
#include <krb5.h>
#include <memory.h>  
#define PAM_SM_PASSWORD
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>


cfg_opt_t opts[] = {
    CFG_STR("ldapserver", NULL, CFGF_NODEFAULT),
    CFG_STR("ldapbinddn", NULL, CFGF_NODEFAULT),
    CFG_STR("ldapbindpw", NULL, CFGF_NODEFAULT),
    CFG_STR("ldapbase", NULL, CFGF_NODEFAULT),
    CFG_STR("krbrealm", NULL, CFGF_NODEFAULT),
    CFG_STR("krbldapbase", NULL, CFGF_NODEFAULT),
    CFG_STR("krbpwuser", NULL, CFGF_NODEFAULT),
    CFG_STR("krbcpwpwd", NULL, CFGF_NODEFAULT),
    CFG_END()
};

char * KRBPRINCIPALKEYATTR[] = {
    "krbprincipalkey",
    NULL
};

int updateauthtoken(char * username, char *password, const char *config) {
    char * tmp;

    int eres = EXIT_SUCCESS;

    cfg_t *cfg;

    cfg = cfg_init(opts, CFGF_NONE);

    if (cfg_parse(cfg, config) == CFG_PARSE_ERROR) {
        eres = EXIT_FAILURE;
        goto exit;
    }

    LDAP *ldap;

    cfg_opt_t * ldapserver = cfg_getopt(cfg, "ldapserver");
    int res = ldap_initialize(&ldap, cfg_opt_getnstr(ldapserver, 0));
    if (res != LDAP_SUCCESS) {
        cfg_free(cfg);
        return EXIT_FAILURE;
    }
    cfg_free_value(ldapserver);

    cfg_opt_t * ldapbinddn = cfg_getopt(cfg, "ldapbinddn");
    cfg_opt_t * ldapbindpw = cfg_getopt(cfg, "ldapbindpw");
    res = ldap_simple_bind_s(ldap, cfg_opt_getnstr(ldapbinddn, 0), cfg_opt_getnstr(ldapbindpw, 0));
    if (res != LDAP_SUCCESS) {
        cfg_free(cfg);
        return EXIT_FAILURE;
    }
    cfg_free_value(ldapbinddn);
    cfg_free_value(ldapbindpw);

    LDAPMessage *result;

    tmp = malloc(sizeof (char)*1024);
    memset(tmp, 0, sizeof (char)*1024);
    cfg_opt_t * krbrealm = cfg_getopt(cfg, "krbrealm");
    sprintf(tmp, "(krbPrincipalName=%s@%s)", username, cfg_opt_getnstr(krbrealm, 0));
    cfg_free_value(krbrealm);
    cfg_opt_t * krbldapbase = cfg_getopt(cfg, "krbldapbase");
    res = ldap_search_ext_s(ldap, cfg_opt_getnstr(krbldapbase, 0), LDAP_SCOPE_SUBTREE, tmp,
            KRBPRINCIPALKEYATTR, 0, NULL, NULL, NULL, 10, &result);
    cfg_free_value(krbldapbase);
    memset(tmp, 0, sizeof (char)*1024);
    free(tmp);

    int ec = ldap_count_entries(ldap, result);

    if (ec < 1) {
        ldap_msgfree(result);
        res = ldap_unbind_s(ldap);
        cfg_free(cfg);
        eres = EXIT_FAILURE;
        goto exit;
    }
    LDAPMessage *msg = ldap_first_message(ldap, result);
    int msgtype = ldap_msgtype(msg);
    if (msgtype != LDAP_RES_SEARCH_ENTRY) {
        ldap_msgfree(msg);
        ldap_msgfree(result);
        res = ldap_unbind_s(ldap);
        cfg_free(cfg);
        eres = EXIT_FAILURE;
        goto exit;
    }



    BerElement *bl;
    char *attrname;
    int keyexits = 0;
    for (attrname = ldap_first_attribute(ldap, msg, &bl); attrname != NULL; attrname = ldap_next_attribute(ldap, msg, bl)) {
        keyexits++;
        ldap_memfree(attrname);
    }
    ber_free(bl, 0);
    ldap_msgfree(msg);

    
    if (keyexits == 1) {
        res = ldap_unbind_s(ldap);
        cfg_free(cfg);
        eres = EXIT_SUCCESS;
        goto exit;
     }

    tmp = malloc(sizeof (char)*1024);
    memset(tmp, 0, sizeof (char)*1024);
    sprintf(tmp, "(uid=%s)", username);
    cfg_opt_t * ldapbase = cfg_getopt(cfg, "ldapbase");
    res = ldap_search_ext_s(ldap, cfg_opt_getnstr(ldapbase, 0), LDAP_SCOPE_SUBTREE, tmp,
            NULL, 0, NULL, NULL, NULL, 1, &result);
    cfg_free_value(ldapbase);
    memset(tmp, 0, sizeof (char)*1024);
    free(tmp);

    ec = ldap_count_entries(ldap, result);

    if (ec < 1) {
        ldap_msgfree(result);
        res = ldap_unbind_s(ldap);
        cfg_free(cfg);
        res = EXIT_FAILURE;
        goto exit;
    }

    msg = ldap_first_message(ldap, result);
    msgtype = ldap_msgtype(msg);

    if (msgtype != LDAP_RES_SEARCH_ENTRY) {
        ldap_msgfree(msg);
        ldap_msgfree(result);
        res = ldap_unbind_s(ldap);
        cfg_free(cfg);
        eres = EXIT_FAILURE;
        goto exit;
    }

    char *userdn = ldap_get_dn(ldap, msg);
    ldap_msgfree(msg);

    res = ldap_simple_bind_s(ldap, userdn, password);
    if (res == LDAP_INVALID_CREDENTIALS) {
        ldap_memfree(userdn);
        res = ldap_unbind_s(ldap);
        cfg_free(cfg);
        eres = EXIT_FAILURE;
        goto exit;
    }
    res = ldap_unbind_s(ldap);
    ldap_memfree(userdn);

    krb5_context krb5ctx = NULL;
    krb5_error_code kres = krb5_init_secure_context(&krb5ctx);

    if (res != 0) {
        cfg_free(cfg);
        eres = EXIT_FAILURE;
        goto exit;
    }

    krb5_creds creds;
    krb5_principal princ;

    memset(&creds, 0, sizeof (krb5_creds));
    cfg_opt_t * krbpwuser = cfg_getopt(cfg, "krbpwuser");
    kres = krb5_parse_name(krb5ctx, cfg_opt_getnstr(krbpwuser, 0), &princ);
    cfg_free_value(krbpwuser);
    if (kres != 0) {
        krb5_free_principal(krb5ctx, princ);
        krb5_free_cred_contents(krb5ctx, &creds);
        krb5_free_context(krb5ctx);
        eres = EXIT_FAILURE;
        goto exit;
    }


    cfg_opt_t * krbcpwpwd = cfg_getopt(cfg, "krbcpwpwd");
    kres = krb5_get_init_creds_password(krb5ctx, &creds, princ, cfg_opt_getnstr(krbcpwpwd, 0), NULL, NULL, 0, "kadmin/changepw", NULL);
    cfg_free_value(krbcpwpwd);
    if (kres != 0) {
        krb5_free_principal(krb5ctx, princ);
        krb5_free_cred_contents(krb5ctx, &creds);
        krb5_free_context(krb5ctx);
        cfg_free(cfg);
        eres = EXIT_FAILURE;
        goto exit;
    }

    int rcode = 0;
    krb5_data rcodes, rs;
    krb5_principal princ_for;
    kres = krb5_parse_name(krb5ctx, username, &princ_for);
    if (kres != 0) {
        krb5_free_principal(krb5ctx, princ);
        krb5_free_principal(krb5ctx, princ_for);
        krb5_free_cred_contents(krb5ctx, &creds);
        krb5_free_context(krb5ctx);
        cfg_free(cfg);
        eres = EXIT_FAILURE;
        goto exit;
    }
    kres = krb5_set_password(krb5ctx, &creds, password, princ_for, &rcode, &rcodes, &rs);

    krb5_free_data_contents(krb5ctx, &rcodes);
    krb5_free_data_contents(krb5ctx, &rs);
    krb5_free_principal(krb5ctx, princ);
    krb5_free_principal(krb5ctx, princ_for);
    krb5_free_cred_contents(krb5ctx, &creds);
    krb5_free_context(krb5ctx);

    cfg_free(cfg);
    eres = EXIT_SUCCESS;

exit:
    return (eres);
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

    const char *config = argv[0];

    char * username;
    if (pam_get_user(pamh, (const char **) &username, NULL) != PAM_SUCCESS) {
        return PAM_IGNORE;
    }

    char * password;
    if (pam_get_authtok(pamh, PAM_AUTHTOK, (const char **) &password, NULL) != PAM_SUCCESS) {
        return PAM_IGNORE;
    }

    if(updateauthtoken(username, password, config) != EXIT_SUCCESS) {
        return PAM_IGNORE;
    }

    return (PAM_SUCCESS);
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return (PAM_IGNORE);
}

