const {Router} = require('express');
const router = Router();
const _ = require('underscore');

// Routes
router.get('/', async (req, res) => { // http://localhost:3000/api/linear

    /**************************************************
     * DATA SET
     **************************************************/
    const valuesX = [1, 2, 3, 5, 6, 8, 9, 10]; 
    const valuesY = [1.5, 2, 4, 4.6, 4.7, 8.5, 8.8, 9];

    /**************************************************
     * COMPUTE PREDICTION
     **************************************************/
    let prediction = await leastSquaresMethod(valuesX.length, valuesX, valuesY);
    res.send(`Prediction: ${prediction}`);
});

async function leastSquaresMethod(N, arrayX, arrayY) {
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
    const bitSizes = [60, 40, 40, 60];
    const bitSize = 40;
    
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
    const relinKey = seal.RelinKeys();
    const galoisKey = seal.GaloisKeys();
    const encryptor = seal.Encryptor(context, publicKey, secretKey);
    const decryptor = seal.Decryptor(context, secretKey);
    const evaluator = seal.Evaluator(context);

    /**************************************************
     * STORE RAW DATA
     **************************************************/
    const trainData = {
        xs: arrayX,
        ys: arrayY
    };

    /**************************************************
     * GUIDE OF FORMULAS TO BE COMPUTED
     * Sx = sum(x[i])
     * Sy = sum(y[i])
     * Sxy = sum(x[i]*y[i])
     * Sxx = sum(x[i]*x[i])
     * Syy = sum(y[i]*y[i])
     **************************************************/

    /**************************************************
     * STORE ARRAY VALUES ENCRYPTED
     **************************************************/
    const scale = Math.pow(2.0, bitSize);

    // Array of each encrypted value on the original X array
    // storeXValues[i] will have the encoded and encrypted form of trainData.xs[i]
    let storeXValues = [];
    for (let i=0; i<N; i++) {
        const plainTextX = seal.PlainText();
        const sealArrayX = Float64Array.from([trainData.xs[i]]);
        encoder.encode(sealArrayX, scale, plainTextX);
        const cipherTextX = encryptor.encryptSymmetric(plainTextX);
        storeXValues[i] = cipherTextX;
    }

    /**************************************************
     * COMPUTE Sx
     **************************************************/
    var cipherTextSx = seal.CipherText();
    const auxPlaintext = seal.PlainText();
    const aux = Float64Array.from([0]);
    encoder.encode(aux, scale, auxPlaintext);
    cipherTextSx = encryptor.encryptSymmetric(auxPlaintext);
    for (let i=0; i<N; i++) {
        evaluator.add(storeXValues[i], cipherTextSx, cipherTextSx);
    }

    // Check correctness of encryption
    const decryptedPlainText = decryptor.decrypt(cipherTextSx);
    const decodedArray = encoder.decode(decryptedPlainText);
    console.log(`Sx: ${decodedArray[0]}`);

    /**************************************************
     * LEAST SQUARES METHOD VARIABLES
     **************************************************/
    let Sx = 0; // Sum of all the X values
    for (let i=0; i<N; i++) {
        Sx += trainData.xs[i];
    }
    let Sy = 0; // Sum of all the Y values
    for (let i=0; i<N; i++) {
        Sy += trainData.ys[i];
    }
    let Sxy = 0; // Sum of all the X*Y values
    for (let i=0; i<N; i++) {
        Sxy += trainData.xs[i]*trainData.ys[i];
    }
    let Sxx = 0; // Sum of all the X^2 values
    for (let i=0; i<N; i++) {
        Sxx += Math.pow(trainData.xs[i], 2);
    }
    let Syy = 0; // Sum of all the Y^2 values
    for (let i=0; i<N; i++) {
        Syy += Math.pow(trainData.ys[i], 2);
    }

    /**************************************************
     * LINEAR CORRELATION COEFFICIENT
     * If r is too low, linear regression is not a good option for this dataset
     **************************************************/
    let r = (N*Sxy-Sx*Sy)/(Math.sqrt(N*Sxx-Sx*Sx)*Math.sqrt(N*Syy-Sy*Sy));
    console.log(`Linear correlation coefficient r: ${r}`);

    /**************************************************
     * SLOPE
     **************************************************/
    let m = (N*Sxy-Sx*Sy)/(N*Sxx-Sx*Sx);

    /**************************************************
     * CUT POINT Y AXIS
     **************************************************/
    let b = (Sy*Sxx-Sx*Sxy)/(N*Sxx-Sx*Sx);

    /**************************************************
     * ERRORS
     **************************************************/
    let beta_sq = 0;
    for (let i=0; i<N; i++) {
        beta_sq += Math.pow(b + m*trainData.xs[i] - trainData.ys[i], 2);
    }

    let e_m = Math.sqrt((N/(N*Sxx-Sx*Sx))*(beta_sq/(N-2)));
    console.log(`Slope error: ${e_m}`);

    let e_b = Math.sqrt((Sxx/(N*Sxx-Sx*Sx))*(beta_sq/(N-2)));
    console.log(`Y axis cut point error: ${e_b}`);

    /**************************************************
     * FINAL PREDICTION EQUATION
     * y = mx + b
     * y = (m +- e_m)x + (b +- e_b)
     **************************************************/
    let x = 11;
    let prediction = m*x + b;
    return prediction;
}

/**************************************************
 * EXPORT
 **************************************************/
module.exports = router;