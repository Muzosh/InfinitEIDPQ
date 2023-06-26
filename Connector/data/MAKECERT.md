# How to create trusted self-signed root certificate

1. `openssl req -x509 -new -newkey dilithium5 -keyout dil5.key -out dil5.crt -nodes -days 365`

    > You are about to be asked to enter information that will be incorporated
    into your certificate request.
    What you are about to enter is what is called a Distinguished Name or a DN.
    There are quite a few fields but you can leave some blank
    For some fields there will be a default value,
    If you enter '.', the field will be left blank.

    > Country Name (2 letter code) [AU]:**CZ**\
    State or Province Name (full name) [Some-State]:**Czechia**\
    Locality Name (eg, city) []:**Brno**\
    Organization Name (eg, company) [Internet Widgits Pty Ltd]:**Cybernetica AS**\
    Organizational Unit Name (eg, section) []:**R&D**\
    Common Name (e.g. server FQDN or YOUR name) []:**PQC Web-eID Nextcloud Root CA**\
    Email Address []:**petr.muzikant@vut.cz**

    > Please enter the following 'extra' attributes
    to be sent with your certificate request\
    A challenge password []:**nextcloudadmin**\
    An optional company name []:

2. `openssl x509 -in dil5.crt -pubkey -noout > dil5.pem`