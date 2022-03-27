const {Router} = require('express');
const router = Router();
const _ = require('underscore');

const samples = require('../sample.json');

/**************************************************
 * ROUTES
 **************************************************/

/**
 * GET
 */
 router.get('/', (req, res) => {
     /**************************************************
     * URL FORMAT
     * Obtained from the query
     * 
     * http://localhost:3000/api/compute-linear/
     * ?title=graph&predict=x
     **************************************************/

    /**************************************************
     * DATA SET
     * 
     * Obtained from the query
     **************************************************/
    const title = req.query.title;
    const predict = req.query.predict;

    /**************************************************
     * FUNCTION TO COMPUTE PREDICTION
     **************************************************/
    var predicted = 0;

    if (title && predict) {
        if (samples.length != 0) {
            _.each(samples, async (sample, _index) => {
                if (sample.title == title) {
                    predicted = await computePrediction(predict, sample.slope, sample.yaxis_cutpoint);
                    res.json({titulo: title, height: predict, weight: predicted});
                } else {
                    res.status(500).json({error: "Title does not match any other on the database."});
                }
            });
        } else {
            res.status(500).json({error: "Database is empty."});
        }
    } else {
        res.status(500).json({error: "Title and X value for prediction are required."});
    }
});

async function computePrediction(x, m, b) {
    /**************************************************
     * SEAL PARAMETERS INITIALIZATION
     **************************************************/
    const SEAL = require('node-seal');
    const seal = await SEAL();

    /**************************************************
     * SCHEME PARAMETERS
     **************************************************/
    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 8192;
    const bitSizes = [50, 30, 30, 30, 50];
    const bitSize = 30;

    const scale = Math.pow(2.0, bitSize);
    
    const parms = seal.EncryptionParameters(schemeType);
    
    /**************************************************
     * POLY MODULUS DEGREE
     **************************************************/
    parms.setPolyModulusDegree(polyModulusDegree);
    
    /**************************************************
     * COEFF MODULUS PRIMES
     **************************************************/
    parms.setCoeffModulus(
        seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
    );
    
    /**************************************************
     * CREATE CONTEXT
     **************************************************/
    const context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        securityLevel // Enforce a security level
    );
    
    /**************************************************
     * CHECK CORRECTNESS AND RETURN CONTEXT
     **************************************************/
    if (!context.parametersSet()) {
        throw new Error(
        'Could not set the parameters in the given context. Please try different encryption parameters.'
        )
    }

    /**************************************************
     * HOMOMORPHIC OBJECTS INITIALIZATION
     **************************************************/
    const encoder = seal.CKKSEncoder(context);
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();
    const relinKey = keyGenerator.createRelinKeys();
    const encryptor = seal.Encryptor(context, publicKey, secretKey);
    const decryptor = seal.Decryptor(context, secretKey);
    const evaluator = seal.Evaluator(context);

    /**************************************************
     * FORMULA TO BE COMPUTED
     * 
     * y = mx + b
     **************************************************/
    // PlainTexts
    const mPlainText = seal.PlainText();
    const xPlainText = seal.PlainText();
    const bPlainText = seal.PlainText();

    // Float arrays for the encoding
    const mArray = Float64Array.from([m]);
    const xArray = Float64Array.from([x]);
    const bArray = Float64Array.from([b]);

    // Encoding
    encoder.encode(mArray, scale, mPlainText);
    encoder.encode(xArray, scale, xPlainText);
    encoder.encode(bArray, scale, bPlainText);

    // CipherTexts
    var cipherTextm = seal.CipherText();
    var cipherTextx = seal.CipherText();
    var cipherTextb = seal.CipherText();

    // Encrypting
    cipherTextm = encryptor.encryptSymmetric(mPlainText);
    cipherTextx = encryptor.encryptSymmetric(xPlainText);
    cipherTextb = encryptor.encryptSymmetric(bPlainText);

    // Compute aux = m*x
    var cipherTextaux = seal.CipherText();
    cipherTextaux = evaluator.multiply(cipherTextm, cipherTextx);
    const cipherTextauxRelin = evaluator.relinearize(cipherTextaux, relinKey);
    const cipherTextauxRescale = evaluator.rescaleToNext(cipherTextauxRelin);

    // Rescale and mod switch b to match mx
    cipherTextb.setScale(cipherTextauxRescale.scale);
    const cipherTextbModSwitch = evaluator.cipherModSwitchTo(cipherTextb, cipherTextauxRescale.parmsId);

    // Compute prediction
    let cipherTextPrediction = seal.CipherText();
    evaluator.add(cipherTextauxRescale, cipherTextbModSwitch, cipherTextPrediction);

    // Return prediction
    const decryptedPrediction = decryptor.decrypt(cipherTextPrediction);
    const decodedPrediction = encoder.decode(decryptedPrediction);

    return decodedPrediction[0];
}

/**************************************************
 * EXPORT
 **************************************************/
module.exports = router;