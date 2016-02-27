# LDAPTOTPServer
A small LDAP perl server that implements TOTP (and TOTP caching) for authenticating with HTTP auth requests.

It's main purpose is to be used as authenticator for apache2 and lighttpd web servers.
Both of these servers support ldap authentication modules for authenticating user against ldap directories.
The web servers need to be configured to use LDAP as source of authenticating/authorizing users.

The LDAPTOTPServer implements a LDAP server based on NET::LDAP::Server. It adds the functionality for users
with http credentials (username/password) to enter a TOTP code (username/passwordTOTP) by adding it directly
to the password.

A local text file (representing the LDAP database) is used to check the credentials and to keep the TOTP seed.
As the TOTP token will eventually be changed (currently 30s) it would require the user to reenter the
credentials (and the curren TOTP token). To avoid this the LDAPTOTPServer keeps track of the first and all
following requests with the first given TOTP token and allows access as long as the requests keep within a certain
time frame (session timeout).

# Web Server configuration example
## Apache2:
Make sure the mod_authnz_ldap module is loaded.
Add the following to your configuration to switch to LDAP authentication:
...
<Location /test>
    Order allow,deny
    Allow from all
    Authtype Basic
    AuthBasicProvider ldap
    AuthLDAPURL "ldap://127.0.0.1:389/ou=totpusergroup?uid?sub?(objectClass=*)"
    Require valid-user
    AuthName "TOTP protected area"
</Location>
...

## Lighttp:
Make sure the mod_auth module is loaded and loaded befroe the mod_fastcgi module (if you enabled it).
Add the following to your configuration to switch to LDAP authentication:
...
auth.backend                 = "ldap"
auth.backend.ldap.hostname   = "127.0.0.1"
auth.backend.ldap.base-dn    = "ou=marcel.dyn.myiq.de"
auth.backend.ldap.filter     = "(uid=$)"
...
Follow the usual steps of defining password protected areas based on the online documentation.


## Nginx:
Is not directly supported. It does have an http auth module that allows a sub request to ask another
web server if the given credentials are ok. One could (later) write a small script to make that translation
but it is also possible to simply use a Lighttpd installation for this which can be configured to use LDAP.
For the location /private defined in Nginx this could look like this (Lighttpd running on 192.168.1.2):
...
location /private/ {
    auth_request /auth;
}
location = /auth {
    proxy_pass http://192.168.1.2/your path at Lighttpd/;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}
...
