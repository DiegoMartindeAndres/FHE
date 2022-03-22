const {Router} = require('express');
const router = Router();
const _ = require('underscore');

// Routes
router.get('/', async (req, res) => { // http://localhost:3000/api/sumckks/?val1=2.2&val2=3

    let val1 = req.query.val1;
    let val2 = req.query.val2;

    // Require SEAL
    const SEAL = require('node-seal');
    const seal = await SEAL();

    // Scheme parameters
    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 8192;
    const bitSizes = [50, 20, 50];
    const bitSize = 20;
    
    const parms = seal.EncryptionParameters(schemeType);
    
    // Set the PolyModulusDegree
    parms.setPolyModulusDegree(polyModulusDegree);
    
    // Create a suitable set of CoeffModulus primes
    parms.setCoeffModulus(
        seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
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
    const encoder = seal.CKKSEncoder(context);
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();
    //const relinKey = seal.RelinKeys();
    const encryptor = seal.Encryptor(context, publicKey, secretKey);
    const decryptor = seal.Decryptor(context, secretKey);
    const evaluator = seal.Evaluator(context);

    // Scale
    const scale = Math.pow(2.0, bitSize);

    // Plaintext
    const plainTextA = seal.PlainText();
    const plainTextB = seal.PlainText();

    // Ciphertexts
    const arrayA = Float64Array.from([val1]);
    encoder.encode(arrayA, scale, plainTextA);
    const cipherTextA = encryptor.encryptSymmetric(plainTextA);

    const arrayB = Float64Array.from([val2]);
    encoder.encode(arrayB, scale, plainTextB);
    const cipherTextB = encryptor.encryptSymmetric(plainTextB);

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