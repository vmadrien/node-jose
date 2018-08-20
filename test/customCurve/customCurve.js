var assert = require('assert');
 
var JWS = require("../../lib/jws");
var JWK = require("../../lib/jwk");

var keyYuri = {
    "kty":"EC",
    "kid":"c6763QMpFR1jLJ9gGkjMFRnwTMzux_v-VzY0Rx5Oal4",
    "use":"sig",
    "crv":"P-256K",
    "key_ops":["sign","verify"],
    "x":"efy2Xj8t46Uo2-sESsuo73cjaR0j6Rttp6BKmYvrP4g",
    "y":"byRbhv8juOlElUnmtV5IDXvi2F0g2YheBzh58P-lv9Y"
  }

var tokenYuri = 
  "eyJhbGciOiJFUzI1NksiLCJqd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NksiLCJraWQiOiJjNjc2M1FNcEZSMWpMSjlnR2tqTUZSbndUTXp1eF92LVZ6WTBSeDVPYWw0Iiwia2V5X29wcyI6WyJzaWduIiwidmVyaWZ5Il0sIngiOiJlZnkyWGo4dDQ2VW8yLXNFU3N1bzczY2phUjBqNlJ0dHA2QkttWXZyUDRnIiwieSI6ImJ5UmJodjhqdU9sRWxVbm10VjVJRFh2aTJGMGcyWWhlQnpoNThQLWx2OVkifX0.eyJzdWIiOiJrb21nbyIsInZlciI6IjAuMC4xIiwiaXNzIjoidmFrdC5pbyIsImlhdCI6MTUzNDM0Nzk1Nn0.8nop0OXMuIOLiUkMB0H8CFRS3XqIzRiR3iQZZbCYsO2H5YrgQKj7h31rL5gv9rjXm6oe8lwbMyvVQG-JrPi5Tw";

  var wrongTokenYuri = 
  "eyJhbGciOiJFUzI1NksiLCJqd2siOnsia3R5IjoiRUMiLCJ1c2UiOiJzaWciLCJjcnYiOiJQLTI1NksiLCJraWQiOiJjNjc2M1FNcEZSMWpMSjlnR2tqTUZSbndUTXp1eF92LVZ6WTBSeDVPYWw0Iiwia2V5X29wcyI6WyJzaWduIiwidmVyaWZ5Il0sIngiOiJlZnkyWGo4dDQ2VW8yLXNFU3N1bzczY2phUjBqNlJ0dHA2QkttWXZyUDRnIiwieSI6ImJ5UmJodjhqdU9sRWxVbm10VjVJRFh2aTJGMGcyWWhlQnpoNThQLWx2OVkifX0.eyJzdWIiOiJrb21nbyIsInZlciI6IjAuMC4xIiwiaXNzIjoidmFrdC5pbyIsImlhdCI6MTUzNDM0Nzk1Nn0.8nop0OXMuIOLiUkMB0H8CFRS3XqIzRiR3iQZZbCYsO2H5YrgQKj7h31rL5gv9rjXm6oe8lwbMyvVQG-JJPi5Tw";
  describe("addcurve",function(){
    
    it("With createdKey",function(done){
            var keystore = JWK.createKeyStore();
            keystore.generate("EC", "P-256K").
                then(function(result) {
                // {result} is a jose.JWK.Key
                key = result;
                var signer = JWS.createSign(key);
                var data = Buffer.from("it's a string","utf8");
                 signer.final(data).then(function(result){
                    var verifier = JWS.createVerify(key);
                    verifier.verify(result).then(function(resultVerif){
                        done();
                    })
                })
                 
        });
    })

it("sign with yhuri",function(done){
    
    JWK.asKey(keyYuri).then(function(result){
        var verifier = JWS.createVerify();
            verifier.verify(tokenYuri, { allowEmbeddedKey: true }).then(function(resultVerif){
                verifier.verify(wrongTokenYuri, { allowEmbeddedKey: true }).then(function(nothing){
                    
                }).catch(function(error){
                    done();
                })
            })
        } )
})


})
