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
router.get('/', (_req, res) => {
    res.json(samples);
});

/**
 * POST
 */
router.post('/', async (req, res) => {
    /**************************************************
     * URL FORMAT
     * Obtained from the query
     * 
     * http://localhost:3000/api/parms-linear/
     * ?valuesX=x1,x2,x3&valuesY=y1,y2,y3&title=graph
     **************************************************/

    /**************************************************
     * DATA SET
     * 
     * Obtained from the query
     **************************************************/
    const valuesX = req.query.valuesX.split(',');
    const valuesY = req.query.valuesY.split(',');
    const title = req.query.title;

    /**************************************************
     * COMPUTE EQUATION PARAMETERS
     **************************************************/
    let leastSqMethod = await leastSquaresMethod(valuesX.length, valuesX, valuesY);
    let m = leastSqMethod[0];
    let b = leastSqMethod[1];

    let existed = false;

    if (title && m && b) {
        _.each(samples, (sample, _index) => {
            if (sample.title == title) {
                existed = true;
            }
        });
    } else if (!title) {
        res.status(500).json({error: "Title unavailable."});
    } else if (!m) {
        res.status(500).json({error: "The slope could not be computed."});
    } else {
        res.status(500).json({error: "The cut point on the Y axis could not be computed."});
    }

    if (!existed) {
        const id = samples.length + 1;
        const newSample = {id, title, slope: m, yaxis_cutpoint: b};
        samples.push(newSample);
        res.json(samples);
    } else {
        res.status(500).json({error: "That title is already in use in the database."});
    }

});

/**
 * PUT
 */
 router.put('/', async (req, res) => {
    /**************************************************
     * URL FORMAT
     * Obtained from the query
     * 
     * http://localhost:3000/api/parms-linear/
     * ?valuesX=x1,x2,x3&valuesY=y1,y2,y3&title=graph
     **************************************************/

    /**************************************************
     * DATA SET
     * 
     * Obtained from the query
     **************************************************/
    const valuesX = req.query.valuesX.split(',');
    const valuesY = req.query.valuesY.split(',');
    const title = req.query.title;

    /**************************************************
     * UPDATE DATABASE GIVEN A TITLE
     **************************************************/
    var found = false;
    var index = 0;

    if (title && valuesX && valuesY) {
        _.each(samples, (sample, i) => {
            if (sample.title == title) {
                index = i;
                found = true;
            }
        });
    } else if (!title) {
        res.status(500).json({error: "Title unavailable."});
    } else {
        res.status(500).json({error: "Arrays unavailable."});
    }

    if (found == false) {
        res.status(500).json({error: "Title does not match any other on the database."});
    } else {
        let leastSqMethod = await leastSquaresMethod(valuesX.length, valuesX, valuesY);
        let m = leastSqMethod[0];
        let b = leastSqMethod[1];
        if (!m) {
            res.status(500).json({error: "The slope could not be computed."});
        } else if (!b) {
            res.status(500).json({error: "The cut point on the Y axis could not be computed."});
        } else {
            samples[index].title = title;
            samples[index].slope = m;
            samples[index].yaxis_cutpoint = b;
            res.json(samples);
        }
    }
});

/**
 * DELETE 
 */
 router.delete('/', (req, res) => {
     /**************************************************
     * URL FORMAT
     * Obtained from the query
     * 
     * http://localhost:3000/api/parms-linear/
     * ?title=graph
     **************************************************/

    /**************************************************
     * DATA SET
     * 
     * Obtained from the query
     **************************************************/
    const title = req.query.title;

    /**************************************************
     * DELETE FROM DATABASE GIVEN A TITLE
     **************************************************/
    var found = false;
    var index = 0;

    if (title) {
        _.each(samples, async (sample, i) => {
            if (sample.title == title) {
                found = true;
                index = i;
            }
        });
    } else {
        res.status(500).json({error: "Title unavailable."});
    }

    if (found == false) {
        res.status(500).json({error: "Title does not match any other on the database."});
    } else {
        samples.splice(index, 1);
        res.json(samples);
    }
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
    const bitSizes = [50, 30, 30, 30, 50];
    const bitSize = 30;
    
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
     * m = (N*Sxy-Sx*Sy)/(N*Sxx-Sx*Sx)
     * b = (Sy*Sxx-Sx*Sxy)/(N*Sxx-Sx*Sx)
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
    const cipherTextSxyauxRelin0 = evaluator.relinearize(cipherTextSxyaux0, relinKey);
    const cipherTextSxyauxRescale0 = evaluator.rescaleToNext(cipherTextSxyauxRelin0);

    evaluator.multiply(storeYValues[1], storeXValues[1], cipherTextSxyaux1);
    const cipherTextSxyauxRelin1 = evaluator.relinearize(cipherTextSxyaux1, relinKey);
    const cipherTextSxyauxRescale1 = evaluator.rescaleToNext(cipherTextSxyauxRelin1);

    evaluator.add(cipherTextSxyauxRescale0, cipherTextSxyauxRescale1, cipherTextSxyauxRescale0);
    cipherTextSxy = cipherTextSxyauxRescale0;

    for (let i=2; i<N; i++) {
        var cipherTextSxyaux = seal.CipherText();
        evaluator.multiply(storeYValues[i], storeXValues[i], cipherTextSxyaux);
        const cipherTextSxyauxRelin = evaluator.relinearize(cipherTextSxyaux, relinKey);
        const cipherTextSxyauxRescale = evaluator.rescaleToNext(cipherTextSxyauxRelin);
        storeXYvalues[i] = cipherTextSxyauxRescale;
    } 

    for (let i=2; i<N; i++) {
        evaluator.add(storeXYvalues[i], cipherTextSxy, cipherTextSxy);
    }

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
    const cipherTextSxxauxRelin0 = evaluator.relinearize(cipherTextSxxaux0, relinKey);
    const cipherTextSxxauxRescale0 = evaluator.rescaleToNext(cipherTextSxxauxRelin0);

    evaluator.multiply(storeXValues[1], storeXValues[1], cipherTextSxxaux1);
    const cipherTextSxxauxRelin1 = evaluator.relinearize(cipherTextSxxaux1, relinKey);
    const cipherTextSxxauxRescale1 = evaluator.rescaleToNext(cipherTextSxxauxRelin1);

    evaluator.add(cipherTextSxxauxRescale0, cipherTextSxxauxRescale1, cipherTextSxxauxRescale0);
    cipherTextSxx = cipherTextSxxauxRescale0;

    for (let i=2; i<N; i++) {
        var cipherTextSxxaux = seal.CipherText();
        evaluator.multiply(storeXValues[i], storeXValues[i], cipherTextSxxaux);
        const cipherTextSxxauxRelin = evaluator.relinearize(cipherTextSxxaux, relinKey);
        const cipherTextSxxauxRescale = evaluator.rescaleToNext(cipherTextSxxauxRelin);
        storeXXvalues[i] = cipherTextSxxauxRescale;
    } 

    for (let i=2; i<N; i++) {
        evaluator.add(storeXXvalues[i], cipherTextSxx, cipherTextSxx);
    }

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
    const cipherTextSyyauxRelin0 = evaluator.relinearize(cipherTextSyyaux0, relinKey);
    const cipherTextSyyauxRescale0 = evaluator.rescaleToNext(cipherTextSyyauxRelin0);

    evaluator.multiply(storeYValues[1], storeYValues[1], cipherTextSyyaux1);
    const cipherTextSyyauxRelin1 = evaluator.relinearize(cipherTextSyyaux1, relinKey);
    const cipherTextSyyauxRescale1 = evaluator.rescaleToNext(cipherTextSyyauxRelin1);

    evaluator.add(cipherTextSyyauxRescale1, cipherTextSyyauxRescale0, cipherTextSyyauxRescale0);
    cipherTextSyy = cipherTextSyyauxRescale0;

    for (let i=2; i<N; i++) {
        var cipherTextSyyaux = seal.CipherText();
        evaluator.multiply(storeYValues[i], storeYValues[i], cipherTextSyyaux);
        const cipherTextSyyauxRelin = evaluator.relinearize(cipherTextSyyaux, relinKey);
        const cipherTextSyyauxRescale = evaluator.rescaleToNext(cipherTextSyyauxRelin);
        storeYYvalues[i] = cipherTextSyyauxRescale;
    } 

    for (let i=2; i<N; i++) {
        evaluator.add(storeYYvalues[i], cipherTextSyy, cipherTextSyy);
    }

    /**************************************************
     * COMPUTE SLOPE
     * m = (N*Sxy-Sx*Sy)/(N*Sxx-Sx*Sx)
     * 
     * Final division will be computed on clear data,
     * as it will be given back to the user in that
     * format.
     * 
     * To compute it homomorphically lets rewrite
     * the expression as follows:
     * mA = N*Sxy
     * mB = Sx*Sy
     * mAB = mA - mB
     * mC = N*Sxx
     * mD = Sx*Sx
     * mCD = mC - mD
     * mE = mAB / mCD
     **************************************************/
    // Turn N into a PlainText
    const NPlaintext = seal.PlainText();
    const NArray = Float64Array.from([N]);
    encoder.encode(NArray, scale, NPlaintext);

    // Compute mA = N*Sxy
    NPlaintext.setScale(cipherTextSxy.scale);
    const NPlaintextModSwitch = evaluator.plainModSwitchToNext(NPlaintext);
    let mA = seal.CipherText();
    evaluator.multiplyPlain(cipherTextSxy, NPlaintextModSwitch, mA);
    const mARelin = evaluator.relinearize(mA, relinKey);
    const mARescale = evaluator.rescaleToNext(mARelin);

    // Compute rB = Sx*Sy
    let mB = seal.CipherText();
    evaluator.multiply(cipherTextSx, cipherTextSy, mB);
    const mBRelin = evaluator.relinearize(mB, relinKey);
    const mBRescale = evaluator.rescaleToNext(mBRelin);

    // Compute mAB = mA - mB
    let mAB = seal.CipherText();
    mBRescale.setScale(mARescale.scale);
    const mBRescaleModSwitch = evaluator.cipherModSwitchTo(mBRescale, mARescale.parmsId);
    evaluator.sub(mARescale, mBRescaleModSwitch, mAB);

    // Compute rC = N*Sxx
    let mC = seal.CipherText();
    evaluator.multiplyPlain(cipherTextSxx, NPlaintextModSwitch, mC);
    const mCRelin = evaluator.relinearize(mC, relinKey);
    const mCRescale = evaluator.rescaleToNext(mCRelin);

    // Compute mD = Sx*Sx
    let mD = seal.CipherText();
    evaluator.multiply(cipherTextSx, cipherTextSx, mD);
    const mDRelin = evaluator.relinearize(mD, relinKey);
    const mDRescale = evaluator.rescaleToNext(mDRelin);

    // Compute mCD = mC - mD
    let mCD = seal.CipherText();
    mDRescale.setScale(mCRescale.scale);
    const mDRescaleModSwitch = evaluator.cipherModSwitchTo(mDRescale, mCRescale.parmsId);
    evaluator.sub(mCRescale, mDRescaleModSwitch, mCD);

    /**************************************************
     * COMPUTE CUT POINT Y AXIS
     * b = (Sy*Sxx-Sx*Sxy)/(N*Sxx-Sx*Sx)
     * 
     * Final division will be computed on clear data,
     * as it will be given back to the user in that
     * format.
     * 
     * To compute it homomorphically lets rewrite
     * the expression as follows:
     * bA = Sy*Sxx
     * bB = Sx*Sxy
     * bAB = bA - bB
     * bC = N*Sxx = mC
     * bD = Sx*Sx = mD
     * bCD = bC - bD = mCD
     * bE = bAB / bCD
     **************************************************/
    // Rescaling and Mod Switching to adapt to Sxx and Sxy
    cipherTextSy.setScale(cipherTextSxx.scale);
    cipherTextSx.setScale(cipherTextSxy.scale);
    const cipherTextSyRescaleModSwitch = evaluator.cipherModSwitchTo(cipherTextSy, cipherTextSxx.parmsId);
    const cipherTextSxRescaleModSwitch = evaluator.cipherModSwitchTo(cipherTextSx, cipherTextSxy.parmsId);
    // Compute bA = Sy*Sxx
    let bA = seal.CipherText();
    evaluator.multiply(cipherTextSyRescaleModSwitch, cipherTextSxx, bA);
    const bARelin = evaluator.relinearize(bA, relinKey);
    const bARescale = evaluator.rescaleToNext(bARelin);

    // Compute bB = Sx*Sxy
    let bB = seal.CipherText();
    evaluator.multiply(cipherTextSxRescaleModSwitch, cipherTextSxy, bB);
    const bBRelin = evaluator.relinearize(bB, relinKey);
    const bBRescale = evaluator.rescaleToNext(bBRelin);

    // Compute bAB = bA - bB
    let bAB = seal.CipherText();
    evaluator.sub(bARescale, bBRescale, bAB);

    /**************************************************
     * FINAL COMPUTATIONS WITH CLEAR DATA
     * 
     * Calculate the slope and the cut point in the
     * Y axis with clear data to be returned to the 
     * user.
     **************************************************/
    // Compute mE = Dec(mAB / mCD)
    const decryptedPlainTextmAB = decryptor.decrypt(mAB);
    const decodedArraymAB = encoder.decode(decryptedPlainTextmAB);
    const decryptedPlainTextmCD = decryptor.decrypt(mCD);
    const decodedArraymCD = encoder.decode(decryptedPlainTextmCD);

    let m = decodedArraymAB[0] / decodedArraymCD[0];

    // Compute bE = Dec(bAB / mCD)
    const decryptedPlainTextbAB = decryptor.decrypt(bAB);
    const decodedArraybAB = encoder.decode(decryptedPlainTextbAB);

    let b = decodedArraybAB[0] / decodedArraymCD[0];

    /**************************************************
     * RETURN SLOPE, CUT POINT AND PREDICTION
     **************************************************/
    return [m, b];
}

/**************************************************
 * EXPORT
 **************************************************/
module.exports = router;