if not sjcl? then throw new Error 'No sjcl library found!'
if sjcl.keyexchange.ssrp? then throw new Error 'Overriding sjcl.keyexchange.ssrp!'

sjcl.keyexchange.ssrp =
    count: 2048 # Number of iterations of the PBKDF.

    _serialize: (point) ->
        point = point.get()
        point = sjcl.codec.base64.fromBits point.x.concat point.y

        return point

    _unserialize: (curve, point) ->
        return new sjcl.ecc.elGamal.publicKey(
            curve,
            sjcl.codec.base64.toBits(point)
        )

    # Generates the user's private key.
    _generatePrivateKey: (password, salt, curve) ->
        length = Math.floor((curve.r.bitLength() - 1) / 8)
        x = sjcl.misc.pbkdf2 password, salt, @count, length

        return new sjcl.bn x

    # Generates a verifier for the user.
    makeVerifier: (username, password, curve)->
        curve = curve || 256

        if "number" is typeof curve
            curve = sjcl.ecc.curves['c' + curve]
            if not curve? then throw new Error 'No such curve!'

        salt = sjcl.random.randomWords 2, 10
        x = @_generatePrivateKey username + '.' + password, salt, curve

        return @_serialize curve.G.mult x

    # Generates a challenge for the user.  Returns a random ElGamal keypair.
    # The `pub` section should be sent to the user while the `sec` section
    # should be kept secret.
    makeChallenge: (curve)->
        kp = sjcl.ecc.elGamal.generateKeys curve
        kp.pub = @_serialize kp.pub

        return kp

    # Calculates the response to the challenge.
    makeResponse: (username, password, salt, chall, curve) ->
        x = @_generatePrivateKey username + '.' + password, salt, curve

        chall = @_unserialize chall
        return @_serialize chall.mult x

    # Verifies the user's response.
    verify: (sec, verifier, resp) ->
        verifier = @_unserialize verifier
        rightResp = @_serialize verifier.mult sec

        return rightResp is resp
