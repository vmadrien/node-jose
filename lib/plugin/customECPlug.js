module.exports = {
   
    curveNameToOid :{
        // "P-256K":"1.3.132.0.10"
    },
    oidToCurveName:{ 
        // "1.3.132.0.10": "P-256K"
    },
    PREFERRED_SIG_ALGO:[
        // {
        //     curve :"P-256K",
        //     algo:"ES256K"
        // }
    ],
    ECDSA_ALGO : [
        // {
        //     name:"ES256K",
        //     curve:"P-256K",
        //     hash:"SHA-256"
        // }
    ],
    NODE_CURVE_MAPPING : [
        // {
        //     curve:"P-256K",
        //     nodejsCurve:"secp256k1"
        // }
    ],
    ELLIPTIC_CURVE : [
        // {
        //     p : "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
        //     a : "0000000000000000000000000000000000000000000000000000000000000000",
        //     b : "0000000000000000000000000000000000000000000000000000000000000007",
        //     n : "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        //     h : "01",
        //     gLeft : "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        //     gRight : "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
        //     curveName : "P-256K"
        // }
    ],

    addEllipticCurve:function(curve,oid,ecdsa_algo,nodeJsCurveName){
            this.ELLIPTIC_CURVE.push(curve);
            this.curveNameToOid[curve.curveName]=oid;
            this.oidToCurveName[oid]=curve.curveName;
            this.ECDSA_ALGO.push(ecdsa_algo);
            this.PREFERRED_SIG_ALGO.push({curve:curve.curveName,algo:ecdsa_algo.name});
            if(nodeJsCurveName==undefined)this.NODE_CURVE_MAPPING.push({curve:curve.curveName,nodejsCurve:curve.curveName});
            else this.NODE_CURVE_MAPPING.push({curve:curve.curveName,nodejsCurve:nodeJsCurveName});
    }
}

