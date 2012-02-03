import sys
import crypt
import ldap, ldap.sasl
from yubico import yubico

import traceback
CLIENT_ID = '1'
CLIENT_KEY = ''

LDAP_YUBI_ATTR = 'yubikeyID'
LDAP_PASSWD_ATTR = 'passwordFactor'

VALIDATOR = yubico.Yubico(CLIENT_ID, CLIENT_KEY, verify_cert=True)
def ldap_connect():
    con = ldap.initialize('ldapi:///')
    try:
        con.sasl_interactive_bind_s('', ldap.sasl.external())
    except:
        print >>sys.stderr, "Unable to bind to LDAP"
        traceback.print_exception(*sys.exc_info())
        return None
    return con

def get_user_info(user):
    """Returns a pair (hashedpass, yubikeyid) for the user"""
    con = ldap_connect()
    if not con:
        return None
    try:
        result = con.search_s(user, ldap.SCOPE_BASE, attrlist=[LDAP_YUBI_ATTR, LDAP_PASSWD_ATTR])
        dn, attrs = result[0]
        return (attrs[LDAP_PASSWD_ATTR][0], attrs[LDAP_YUBI_ATTR][0])
    finally:
        con.unbind()

def validate_auth(user, passwd, service, realm):
    if len(passwd) < 44:
        return False
    otp = passwd[-44:]
    passwd = passwd[:-44]
    try:
        VALIDATOR.verify(otp)
    except:
        traceback.print_exception(*sys.exc_info())
        return False
    yubi_id = otp[:12]
    try:
        (user_passhash, user_yubi_id) = get_user_info(user)
    except:
        print >>sys.stderr, "Unable to retrieve LDAP entry for user {0!r}".format(user)
        traceback.print_exception(*sys.exc_info())
        return False
    if yubi_id != user_yubi_id:
        return False
    if crypt.crypt(passwd, user_passhash) != user_passhash:
        return False
    return True

if __name__ == '__main__':
    result = validate_auth(sys.argv[1], sys.argv[2], None, None)
    print repr(result)
