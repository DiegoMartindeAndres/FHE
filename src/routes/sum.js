const {Router} = require('express');
const router = Router();
const _ = require('underscore');

// Routes
router.get('/', async (req, res) => { // http://localhost:3000/api/sumhe/?val1=2&val2=3

    let val1 = req.query.val1;
    let val2 = req.query.val2;

    // Require SEAL
    const SEAL = require('node-seal');
    const seal = await SEAL();

    // Scheme parameters
    const schemeType = seal.SchemeType.bfv;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 4096;
    const bitSizes = [36, 36, 37];
    const bitSize = 20;
    
    const parms = seal.EncryptionParameters(schemeType);
    
    // Set the PolyModulusDegree
    parms.setPolyModulusDegree(polyModulusDegree);
    
    // Create a suitable set of CoeffModulus primes
    parms.setCoeffModulus(
        seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
    );
    
    // Set the PlainModulus to a prime of bitSize 20
    parms.setPlainModulus(
        seal.PlainModulus.Batching(polyModulusDegree, bitSize)
    );
    
    const context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        securityLevel // Enforce a security level
    );
    
    if (!context.parametersSet()) {
        throw new Error(
        'Could not set the parameters in the given context. Please try different encryption parameters.'
        )
    };
    
    // Homomorphic objects for the computations
    const encoder = seal.BatchEncoder(context);
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();
    const encryptor = seal.Encryptor(context, publicKey);
    const decryptor = seal.Decryptor(context, secretKey);
    const evaluator = seal.Evaluator(context);

    // Ciphertexts
    const arrayA = Int32Array.from([val1]);
    const plainTextA = encoder.encode(arrayA);
    const cipherTextA = encryptor.encrypt(plainTextA);

    const arrayB = Int32Array.from([val2]);
    const plainTextB = encoder.encode(arrayB);
    const cipherTextB = encryptor.encrypt(plainTextB);

    // Add the CipherText to itself and store it in the destination parameter (itself)
    const cipherTextD = seal.CipherText();
    evaluator.add(cipherTextA, cipherTextB, cipherTextD);
    
    // Decrypt the CipherText
    const decryptedPlainText = decryptor.decrypt(cipherTextD);
    
    // Decode the PlainText
    const decodedArray = encoder.decode(decryptedPlainText);
    
    res.send(`${decodedArray[0]}`);
});

// Export
module.exports = router;