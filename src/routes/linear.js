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
     * CHECK VALIDITY OF VALUES TO BE COMPUTED
     **************************************************/
    if (arrayX.length != N ||
        arrayY.length != N ||
        N<0) {
            throw new Error(
                'Array lengths not valid.'
            )
    }

    if (N>0 && N<2) {
            throw new Error(
                'At least length 2 of the arrays is needed.'
            )
    }

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

    // Array of each encrypted value on the original Y array
    // storeYValues[i] will have the encoded and encrypted form of trainData.ys[i]
    let storeYValues = [];
    for (let i=0; i<N; i++) {
        const plainTextY = seal.PlainText();
        const sealArrayY = Float64Array.from([trainData.ys[i]]);
        encoder.encode(sealArrayY, scale, plainTextY);
        const cipherTextY = encryptor.encryptSymmetric(plainTextY);
        storeYValues[i] = cipherTextY;
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
    const decryptedPlainTextSx = decryptor.decrypt(cipherTextSx);
    const decodedArraySx = encoder.decode(decryptedPlainTextSx);
    console.log(`Sx: ${decodedArraySx[0]}`);

    /**************************************************
     * COMPUTE Sy
     **************************************************/
    var cipherTextSy = seal.CipherText();
    cipherTextSy = encryptor.encryptSymmetric(auxPlaintext);
    for (let i=0; i<N; i++) {
        evaluator.add(storeYValues[i], cipherTextSy, cipherTextSy);
    }

    // Check correctness of encryption
    const decryptedPlainTextSy = decryptor.decrypt(cipherTextSy);
    const decodedArraySy = encoder.decode(decryptedPlainTextSy);
    console.log(`Sy: ${decodedArraySy[0]}`);

    /**************************************************
     * COMPUTE Sxy
     **************************************************/
    var cipherTextSxy = seal.CipherText();
    var cipherTextSxyaux = seal.CipherText();
    var cipherTextSxyaux0 = seal.CipherText();
    var cipherTextSxyaux1 = seal.CipherText();
    cipherTextSxy = encryptor.encryptSymmetric(auxPlaintext);

    let storeXYvalues = [];
    evaluator.multiply(storeYValues[0], storeXValues[0], cipherTextSxyaux0);
    evaluator.rescaleToNext(cipherTextSxyaux0);

    evaluator.multiply(storeYValues[1], storeXValues[1], cipherTextSxyaux1);
    evaluator.rescaleToNext(cipherTextSxyaux1);

    evaluator.add(cipherTextSxyaux1, cipherTextSxyaux0, cipherTextSxyaux0);
    cipherTextSxy = cipherTextSxyaux0;

    for (let i=2; i<N; i++) {
        evaluator.multiply(storeYValues[i], storeXValues[i], cipherTextSxyaux);
        evaluator.rescaleToNext(cipherTextSxyaux);
        storeXYvalues[i] = cipherTextSxyaux;
    }

    for (let i=2; i<N; i++) {
        evaluator.add(storeXYvalues[i], cipherTextSxy, cipherTextSxy);
    }

    // Check correctness of encryption
    const decryptedPlainTextSxy = decryptor.decrypt(cipherTextSxy);
    const decodedArraySxy = encoder.decode(decryptedPlainTextSxy);
    console.log(`Sxy: ${decodedArraySxy[0]}`);

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
        console.log(`Real stored ${i}: ${Sxy}`);
    }
    console.log(`Sxy no-fhe: ${Sxy}`);
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