SJCL Small SRP
==============

Small SRP is a password authentication mechanism for web applications that has
the same password-related security properties as SRP but is significantly more
efficient.

1.  Write-up:  http://bren2010.github.io/2014/11/29/small-srp.html
2.  Demo:  http://bren2010.github.io/sjcl-ssrp/


### Documentation

- `makeVerifier(username, password, curve): (salt, verifier)`
  - Generates a salt and a verifier for a user.  Run by the user.  Both of the
    function's outputs should be sent to the server.
- `makeChallenge(curve): {pub: ..., sec: ...}`
  - Generates a challenge to authenticate the user.  Run by the server.  The
    `pub` section is a string and is sent to the user while the `sec` section is
    kept secret.
- `makeResponse(username, password, salt, chall, curve): response`
  - Calculates the user's response string to the server's challenge.  Run by the
    user.  The function's output is sent back to the server.
- `verify(sec, verifier, response, curve): Boolean`
  - Returns true if the user has successfully responded to the challenge and
    should be authenticated or false if the user should be rejected.  Run by the
    server.
