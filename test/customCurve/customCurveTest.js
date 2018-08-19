var assert = require('assert');
var eccDeps = require('../../lib/deps/ecc/curves'); 
var ecdsa = require('../../lib/algorithms/ecdsa');
var ecdh = require('../../lib/algorithms/ecdh');

 //p= 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
 var p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
 var a = "0000000000000000000000000000000000000000000000000000000000000000";
 var b = "0000000000000000000000000000000000000000000000000000000000000007";
 var n = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
 var h = "01";
 var gLeft = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
 var gRight = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
 var curveName  = "secp256k1";

 var key= {
    kty: "EC",
    crv: curveName,
    x: Buffer.from("76b9abfbef14576f65f941ca976f9fd6867b2648ddd6f97c0c486f7e3f8fe64c","hex"),
    y: Buffer.from("0e4aeeab862b60c98e30b255ecf059e615f6962bb29bde083c20a49356237620","hex"),
    d: Buffer.from("14b41b6b49a9b01e0e350cce03188251ae492535c3ab4cb89bed009d34881c2d","hex")
  }

  var keyB= {
    kty: "EC",
    crv: curveName,
    x: Buffer.from("bb7039335c3e6626e2e3b6854debd5b7c036d7fde38869f549ffe6fc9bc6cbc4","hex"),
    y: Buffer.from("7e1ebe3c3d318380c8fd3d40c0f689fe7a5dbdbc70efe836c77613e690f96366","hex"),
    d: Buffer.from("dee85ff184dfdb9b8c5075dda7da2253eb1f7bb8d9583b3b9457cdff39ced22d","hex")
  }
 
describe("addcurve",function(){
    it("should add a custom curve",function(){
          
          eccDeps[curveName] = eccDeps.getX9ECParameters(p,a,b,n,h,gLeft,gRight);
          assert.notEqual(eccDeps[curveName],undefined);
          eccDeps[curveName] = undefined;
    })
    it("should sign with custom curve",function(done){
        var curveName  = "secp256k1";
        var ecdsaAlgName = "MyAlgo";
      
        eccDeps[curveName] = eccDeps.getX9ECParameters(p,a,b,n,h,gLeft,gRight);
        ecdsa.addEcdsaAlgorithm(ecdsaAlgName,curveName,"SHA-256");
        var ecdsaItem = ecdsa[ecdsaAlgName];
        var data = Buffer.from("This is test data","utf8");
        ecdsaItem.sign(key,data).then(function(sig){
            assert.deepEqual(data,sig.data);
            ecdsaItem.verify(key,sig.data,sig.mac).then(function(itVerify){
                assert.equal(true,itVerify.valid);
                ecdsa[ecdsaAlgName] = undefined;
                eccDeps[curveName] = undefined;
                done();
            })
        })  
  })  

  it.only("should derive shared secret",function(done){
    eccDeps[curveName] = eccDeps.getX9ECParameters(p,a,b,n,h,gLeft,gRight);
      ecdh.addNodeJsECCurveNameMapping(curveName,curveName);
    ecdh["ECDH-ES"].encrypt(keyB,undefined,{epk:key,enc:"A256GCM"}).then(function(sharedEnc){
        ecdh["ECDH-ES"].decrypt(keyB,undefined,{epk:key,enc:"A256GCM"}).then(function(sharedDec){
            assert.deepEqual(sharedEnc.data,sharedDec);
            ecdh.addNodeJsECCurveNameMapping(curveName,undefined);
            done(); 
        })
    })
})
})
