This project is based on [lite-idp](https://github.com/amdonov/lite-idp), but adds the following features:
- LDAP User Password Validator
- SP Metadata is automatically read during startup

The added configuration items are similar to：
```yaml
sp-medata-urls:
  - url: http://localhost:7777/sso/api/v1/saml/metadata
ldap:
    addr: ldap://localhost:30063
    binddn: cn=admin,dc=aiframe,dc=com
    binddn_credential: xxxxxxxxx
    search_base: ou=people,dc=aiframe,dc=com
```
Refer to this link for usage more details: https://github.com/amdonov/lite-idp/blob/master/README.adoc