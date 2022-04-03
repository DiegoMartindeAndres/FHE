const {Router} = require('express');
const router = Router();
const _ = require('underscore');

router.post('/', async (req, res) => {

    // Receive parameters
    const arrayX = req.body.valuesX;
    const arrayY = req.body.valuesY;
    const N = arrayX.length;
    const relinBase64Key = req.body.relinBase64Key;
    const publicBase64Key = req.body.publicBase64Key;

    /**************************************************
     * CHECK VALIDITY OF VALUES TO BE COMPUTED
     **************************************************/
     if (arrayX.length !=
        arrayY.length ) {
            throw new Error(
                'El tamaño de los arrays es distinto.'
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
    const publicKey = seal.PublicKey();
    publicKey.load(context, publicBase64Key);
    const encryptor = seal.Encryptor(context, publicKey);
    const relinKey = seal.RelinKeys();
    relinKey.load(context, relinBase64Key);
    const evaluator = seal.Evaluator(context);
 
     /**************************************************
     * BASE64CIPHERTEXTS TO CIPHERTEXTS
     **************************************************/
    let storeXValues = [];
    for (let i=0; i<N; i++) {
        const uploadedCipherText = seal.CipherText();
        uploadedCipherText.load(context, arrayX[i]);
        storeXValues[i] = uploadedCipherText;
    }

    let storeYValues = [];
    for (let i=0; i<N; i++) {
        const uploadedCipherText = seal.CipherText();
        uploadedCipherText.load(context, arrayY[i]);
        storeYValues[i] = uploadedCipherText;
    }

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
     * SCALE
     **************************************************/
    const scale = Math.pow(2.0, bitSize);

    /**************************************************
     * COMPUTE Sx
     * Sx = sum(x[i])
     * The sum of all the values in the X array
     **************************************************/
    var cipherTextSx = seal.CipherText();
    const auxPlaintext = seal.PlainText();
    const aux = Float64Array.from([0]);
    encoder.encode(aux, scale, auxPlaintext);
    cipherTextSx = encryptor.encrypt(auxPlaintext);
    for (let i=0; i<N; i++) {
        evaluator.add(storeXValues[i], cipherTextSx, cipherTextSx);
    }

    /**************************************************
     * COMPUTE Sy
     * Sy = sum(y[i])
     * The sum of all the values in the Y array
     **************************************************/
    var cipherTextSy = seal.CipherText();
    cipherTextSy = encryptor.encrypt(auxPlaintext);
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
    cipherTextSxy = encryptor.encrypt(auxPlaintext);

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
    cipherTextSxx = encryptor.encrypt(auxPlaintext);

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
    cipherTextSyy = encryptor.encrypt(auxPlaintext);

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
     * RETURN SLOPE AND CUT POINT NUMERATOR
     * AND DENOMINATOR
     **************************************************/
    const mABBase64 = mAB.save();
    const bABBase64 = bAB.save();
    const mCDBase64 = mCD.save();

    res.json({numeratorSlope: mABBase64, numeratorCutPoint: bABBase64, denominator: mCDBase64});
})

/**************************************************
 * EXPORT
 **************************************************/
module.exports = router;