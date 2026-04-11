// Minimal TLS 1.2 test server on port 42230
// Uses our cert signed by the CA installed in Windows trust store
const tls = require('tls');

const options = {
    key: `-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALzDAOVQ7Jw7OqN8
coYHgxMXvr6I1y0yc3BKEF7pPmI7RAVpdmnz/FE6afVmskY3vK9pp2S6cZGVlJMQ
GMrn8/BPZ1+SuNGb5y18RQGd7xbvSTOXtD0TLjguGAoLnFZLrMud/F05OwRPl1mq
Gxl7B46s3o2JvdvPwINZhENpZ4j5AgMBAAECgYAh2fLKLSYRqomMkh/Tq3s1LFf3
wYCdSWPsakvfSYL3iNtdARnMTIYeZxRjfwRPlWVQK+lqJgmB60pWyVc45DoZuoFn
Fbgfkwpnngw9BmSI/pRj4aFHp06ZMK27IIuscXftZgTGbA8UFZWSFMbdif+5QS2G
6heGt66MsgD7+/a7FQJBAO0ewv37N/nG+1UmKKiu/iB3UtJWEwMO2B5mBO6C+LEY
Dj1TYG2D/qhdZAt9DKGO0EGJ5a8nal0k+I65QAZW7/8CQQDLyoxZ3DgBGCTmUrrX
jLz5Trhz4QtQ9gtpZN+fEx1SsYQohmN6ajHrwlHsOgWZYl5XqqXQjvnnw/BerP+T
iQcHAkEA6lDtq4Gm7OLe1mPg5eAXLAn+A/Ae1XTDyDZURUWTb50v5RYRQeefrMys
4lVuN/Aih8E3AYDXsLeqD4+sXxdmDQJAZDvJcGE6Qn+HlqlWMLKON+kaHBSyJi3+
SuZMfsc+AvBA2lXPE+SrjRPUi2W2X0zcri3GxJ+uFupujYJ1ajFZfQJAQjTpKEgr
ij1CWxOW216skkJ+ZMgHCoTLSErtKHgh/5zKqdirMxLC+E5fI+X5ATtULHMJuxkN
uhzxncOy73TVwg==
-----END PRIVATE KEY-----`,
    cert: `-----BEGIN CERTIFICATE-----
MIIC+DCCAmGgAwIBAgIURlB3i8E67F4x/Zr1/rF062GzDBYwDQYJKoZIhvcNAQEF
BQAwgaAxIDAeBgNVBAsMF09ubGluZSBUZWNobm9sb2d5IEdyb3VwMR4wHAYDVQQK
DBVFbGVjdHJvbmljIEFydHMsIEluYy4xFTATBgNVBAcMDFJlZHdvb2QgQ2l0eTET
MBEGA1UECAwKQ2FsaWZvcm5pYTELMAkGA1UEBhMCVVMxIzAhBgNVBAMMGk9URzMg
Q2VydGlmaWNhdGUgQXV0aG9yaXR5MCAXDTI2MDQxMDEyNTM1NVoYDzIwNTMwODI2
MTI1MzU1WjCBiTEmMCQGA1UEAwwdd2ludGVyMTUuZ29zcmVkaXJlY3Rvci5lYS5j
b20xHTAbBgNVBAsMFEdsb2JhbCBPbmxpbmUgU3R1ZGlvMR4wHAYDVQQKDBVFbGVj
dHJvbmljIEFydHMsIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWExCzAJBgNVBAYT
AlVTMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8wwDlUOycOzqjfHKGB4MT
F76+iNctMnNwShBe6T5iO0QFaXZp8/xROmn1ZrJGN7yvaadkunGRlZSTEBjK5/Pw
T2dfkrjRm+ctfEUBne8W70kzl7Q9Ey44LhgKC5xWS6zLnfxdOTsET5dZqhsZeweO
rN6Nib3bz8CDWYRDaWeI+QIDAQABo0IwQDAdBgNVHQ4EFgQUDWC2DVufAaCIrHGz
QFSmS+aAytYwHwYDVR0jBBgwFoAUjlGkQPsyNRMPRkr5wuTWq78fkaAwDQYJKoZI
hvcNAQEFBQADgYEAg3E1pK6ihH2Ar6Ekek5F0lcevoZCUk2dqq+ZNrW5ZsN/Pa26
eG8hj4F3sCUzXITcKpCl/EDQWv0/Y4kP3rwth8/ptypLsrp6qKJ0IpDfOHjzpZBc
S6HyjVVkyf7iZ2PZNpTDv4/DI7wQkPdAROkFl6kEAO5hE8FRxuoJD43wDXw=
-----END CERTIFICATE-----`,
    // Allow all TLS versions and ciphers
    minVersion: 'TLSv1',
    ciphers: 'ALL:@SECLEVEL=0',
    rejectUnauthorized: false,
};

const server = tls.createServer(options, function(socket) {
    console.log('TLS CONNECTED! proto=' + socket.getProtocol() + ' cipher=' + JSON.stringify(socket.getCipher()));
    socket.on('data', function(d) {
        console.log('Received ' + d.length + ' bytes: ' + d.toString('hex').substring(0, 100));
    });
    socket.on('end', function() { console.log('Client ended'); });
});

server.on('tlsClientError', function(err) {
    console.log('TLS ERROR: ' + err.message + ' code=' + err.code);
    // Print the full error for debugging
    console.log('Full error: ' + JSON.stringify(err, Object.getOwnPropertyNames(err)));
});

// Also log raw TCP connections to see what bytes arrive
server.on('connection', function(socket) {
    console.log('TCP connection from ' + socket.remoteAddress);
    var origPush = socket.push;
    var firstData = true;
    socket.on('data', function(d) {
        if (firstData) {
            console.log('First raw bytes: ' + d.toString('hex').substring(0, 60));
            firstData = false;
        }
    });
});

server.listen(42230, '0.0.0.0', function() {
    console.log('TLS server on port 42230. Launch FIFA 17...');
});
