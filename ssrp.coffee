if not sjcl? then throw new Error 'No sjcl library found!'
if sjcl.keyexchange.ssrp? then throw new Error 'Overriding sjcl.keyexchange.ssrp!'

sjcl.keyexchange.ssrp =
    count: 2048 # Number of iterations of the PBKDF.

    _serialize: (point) ->
        if point.get?
            point = point.get()
            point = sjcl.codec.base64.fromBits point.x.concat point.y

            return point
        else return sjcl.codec.base64.fromBits point.toBits()

    _unserialize: (point, curve) ->
        return curve.fromBits sjcl.codec.base64.toBits point

    # Generates the user's private key.
    _generatePrivateKey: (password, salt, curve) ->
        length = Math.floor((curve.r.bitLength() - 1) / 8)
        x = sjcl.misc.pbkdf2 password, salt, @count, length

        return new sjcl.bn '0x' + sjcl.codec.hex.fromBits x

    # Generates a verifier for the user.
    makeVerifier: (username, password, curve)->
        curve = curve || 256

        if "number" is typeof curve
            curve = sjcl.ecc.curves['c' + curve]
            if not curve? then throw new Error 'No such curve!'

        salt = sjcl.random.randomWords 2, 10
        x = @_generatePrivateKey username + '.' + password, salt, curve

        return [sjcl.codec.base64.fromBits(salt), @_serialize(curve.G.mult(x))]

    # Generates a challenge for the user.  Returns a random ElGamal keypair.
    # The `pub` section should be sent to the user while the `sec` section
    # should be kept secret.
    makeChallenge: (curve)->
        sec = sjcl.bn.random curve.r
        pub = @_serialize curve.G.mult sec

        return pub: pub, sec: sec

    # Calculates the response to the challenge.
    makeResponse: (username, password, salt, chall, curve) ->
        salt = sjcl.codec.base64.toBits salt
        x = @_generatePrivateKey username + '.' + password, salt, curve

        chall = @_unserialize chall, curve
        return @_serialize chall.mult x

    # Verifies the user's response.
    verify: (sec, verifier, resp, curve) ->
        verifier = @_unserialize verifier, curve
        rightResp = @_serialize verifier.mult sec

        return rightResp is resp
