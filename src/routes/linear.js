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
    const relinKey = keyGenerator.createRelinKeys();
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
     * GUIDE OF FORMULAS TO BE COMPUTED FOR THE
     * LEAST SQUARES METHOD
     * Sx = sum(x[i])
     * Sy = sum(y[i])
     * Sxy = sum(x[i]*y[i])
     * Sxx = sum(x[i]*x[i])
     * Syy = sum(y[i]*y[i])
     * r = (N*Sxy-Sx*Sy)/(Math.sqrt(N*Sxx-Sx*Sx)*Math.sqrt(N*Syy-Sy*Sy))
     * m = (N*Sxy-Sx*Sy)/(N*Sxx-Sx*Sx)
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
     * Sx = sum(x[i])
     * The sum of all the values in the X array
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
     * Sy = sum(y[i])
     * The sum of all the values in the Y array
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
     * Sxy = sum(x[i]*y[i])
     * The sum of all the products of the values in 
     * the X array times the ones in the Y array
     **************************************************/
    var cipherTextSxy = seal.CipherText();
    var cipherTextSxyaux0 = seal.CipherText();
    var cipherTextSxyaux1 = seal.CipherText();
    cipherTextSxy = encryptor.encryptSymmetric(auxPlaintext);

    let storeXYvalues = [];
    evaluator.multiply(storeYValues[0], storeXValues[0], cipherTextSxyaux0);
    evaluator.relinearize(cipherTextSxyaux0, relinKey);
    evaluator.rescaleToNext(cipherTextSxyaux0);

    evaluator.multiply(storeYValues[1], storeXValues[1], cipherTextSxyaux1);
    evaluator.relinearize(cipherTextSxyaux1, relinKey);
    evaluator.rescaleToNext(cipherTextSxyaux1);

    evaluator.add(cipherTextSxyaux1, cipherTextSxyaux0, cipherTextSxyaux0);
    cipherTextSxy = cipherTextSxyaux0;

    for (let i=2; i<N; i++) {
        var cipherTextSxyaux = seal.CipherText();
        evaluator.multiply(storeYValues[i], storeXValues[i], cipherTextSxyaux);
        evaluator.relinearize(cipherTextSxyaux, relinKey);
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
     * COMPUTE Sxx
     * Sxx = sum(x[i]*x[i])
     * The sum of all the products of the values in 
     * the X array times themselves
     **************************************************/
    var cipherTextSxx = seal.CipherText();
    var cipherTextSxxaux0 = seal.CipherText();
    var cipherTextSxxaux1 = seal.CipherText();
    cipherTextSxx = encryptor.encryptSymmetric(auxPlaintext);

    let storeXXvalues = [];
    evaluator.multiply(storeXValues[0], storeXValues[0], cipherTextSxxaux0);
    evaluator.relinearize(cipherTextSxxaux0, relinKey);
    evaluator.rescaleToNext(cipherTextSxxaux0);

    evaluator.multiply(storeXValues[1], storeXValues[1], cipherTextSxxaux1);
    evaluator.relinearize(cipherTextSxxaux1, relinKey);
    evaluator.rescaleToNext(cipherTextSxxaux1);

    evaluator.add(cipherTextSxxaux1, cipherTextSxxaux0, cipherTextSxxaux0);
    cipherTextSxx = cipherTextSxxaux0;

    for (let i=2; i<N; i++) {
        var cipherTextSxxaux = seal.CipherText();
        evaluator.multiply(storeXValues[i], storeXValues[i], cipherTextSxxaux);
        evaluator.relinearize(cipherTextSxxaux, relinKey);
        evaluator.rescaleToNext(cipherTextSxxaux);
        storeXXvalues[i] = cipherTextSxxaux;
    } 

    for (let i=2; i<N; i++) {
        evaluator.add(storeXXvalues[i], cipherTextSxx, cipherTextSxx);
    }

    // Check correctness of encryption
    const decryptedPlainTextSxx = decryptor.decrypt(cipherTextSxx);
    const decodedArraySxx = encoder.decode(decryptedPlainTextSxx);
    console.log(`Sxx: ${decodedArraySxx[0]}`);

/**************************************************
 * COMPUTE Syy
 * Syy = sum(y[i]*y[i])
 * The sum of all the products of the values in 
 * the Y array times themselves
 **************************************************/
    var cipherTextSyy = seal.CipherText();
    var cipherTextSyyaux0 = seal.CipherText();
    var cipherTextSyyaux1 = seal.CipherText();
    cipherTextSyy = encryptor.encryptSymmetric(auxPlaintext);

    let storeYYvalues = [];
    evaluator.multiply(storeYValues[0], storeYValues[0], cipherTextSyyaux0);
    evaluator.relinearize(cipherTextSyyaux0, relinKey);
    evaluator.rescaleToNext(cipherTextSyyaux0);

    evaluator.multiply(storeYValues[1], storeYValues[1], cipherTextSyyaux1);
    evaluator.relinearize(cipherTextSyyaux1, relinKey);
    evaluator.rescaleToNext(cipherTextSyyaux1);

    evaluator.add(cipherTextSyyaux1, cipherTextSyyaux0, cipherTextSyyaux0);
    cipherTextSyy = cipherTextSyyaux0;

    for (let i=2; i<N; i++) {
    var cipherTextSyyaux = seal.CipherText();
    evaluator.multiply(storeYValues[i], storeYValues[i], cipherTextSyyaux);
    evaluator.relinearize(cipherTextSyyaux, relinKey);
    evaluator.rescaleToNext(cipherTextSyyaux);
    storeYYvalues[i] = cipherTextSyyaux;
    } 

    for (let i=2; i<N; i++) {
    evaluator.add(storeYYvalues[i], cipherTextSyy, cipherTextSyy);
    }

    // Check correctness of encryption
    const decryptedPlainTextSyy = decryptor.decrypt(cipherTextSyy);
    const decodedArraySyy = encoder.decode(decryptedPlainTextSyy);
    console.log(`Syy: ${decodedArraySyy[0]}`);

    /**************************************************
     * COMPUTE CORRELATION COEFFICIENT
     * r = (N*Sxy-Sx*Sy)/(Math.sqrt(N*Sxx-Sx*Sx)
     *      *Math.sqrt(N*Syy-Sy*Sy))
     * If r is too low, linear regression is not a 
     * good option for this dataset
     * 
     * To compute it homomorphically lets rewrite
     * the expression as follows:
     * rA = N*Sxy
     * rB = Sx*Sy
     * rAB = rA - rB
     * rC = N*Sxx
     * rD = Sx*Sx
     * rCD = rC - rD
     * rE = rCD ^ 1/2
     * rF = N*Syy
     * rG = Sy*Sy
     * rFG = rF - rG
     * rH = rFG ^ 1/2
     * rI = rE * rH
     * rJ = rI ^ (-1)
     * r = rAB*rJ
     **************************************************/
    // Turn N into a PlainText
    const NPlaintext = seal.PlainText();
    const NArray = Float64Array.from([N]);
    encoder.encode(NArray, scale, NPlaintext);

    console.log(`Scale Sxy: ${cipherTextSxy.scale}`);
    console.log(`Scale N: ${NPlaintext.scale}`);

    // Compute rA = N*Sxy
    let rA = seal.CipherText();
    evaluator.multiplyPlain(cipherTextSxy, NPlaintext, rA);
    evaluator.relinearize(rA, relinKey);
    evaluator.rescaleToNext(rA);

    // Compute rB = Sx*Sy
    let rB = seal.CipherText();
    evaluator.multiply(cipherTextSx, cipherTextSy, rB);
    evaluator.relinearize(rB, relinKey);
    evaluator.rescaleToNext(rB);

    // Compute rAB = rA - rB
    let rAB = seal.CipherText();
    //rA.setScale(rB.scale);
    console.log(`Scale A: ${rA.scale}`);
    console.log(`Scale B: ${rB.scale}`);
    console.log(`Scale AB: ${rAB.scale}`);
    //evaluator.sub(rA, rB, rAB);




    // Check correctness of encryption
    const decryptedPlainTextPrueba = decryptor.decrypt(rA);
    const decodedArrayPrueba = encoder.decode(decryptedPlainTextPrueba);
    console.log(`PRUEBA FHE: ${decodedArrayPrueba[0]}`);

    /**************************************************
     * COMPUTE SLOPE
     * m = (N*Sxy-Sx*Sy)/(N*Sxx-Sx*Sx)
     **************************************************/

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
    console.log(`PUEBA: ${N*Sxy-Sx*Sy}`);
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