const {Router} = require('express');
const router = Router();
const _ = require('underscore');

/**************************************************
 * POST
 **************************************************/
router.post('/', async (req, res) => {

    /**************************************************
     * RECEIVE PARAMETERS FROM BODY
     **************************************************/
    const arrayX = req.body.valuesX;
    const arrayY = req.body.valuesY;
    const N = arrayX.length;
    const scale = req.body.scale;
    const parmsBase64 = req.body.parmsBase64;
    const secLevel = req.body.secLevel;
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
    const parms = seal.EncryptionParameters();
    parms.load(parmsBase64);
    
    /**************************************************
     * CREATE CONTEXT
     **************************************************/
    var securityLevel = null;
    if (secLevel === 'tc128') {
        securityLevel = seal.SecurityLevel.tc128;
    } else if (secLevel === 'tc192') {
        securityLevel = seal.SecurityLevel.tc192;
    } else {
        securityLevel = seal.SecurityLevel.tc256;
    }
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
    cipherTextSxyaux0.delete();
    cipherTextSxyauxRelin0.delete();

    evaluator.multiply(storeYValues[1], storeXValues[1], cipherTextSxyaux1);
    const cipherTextSxyauxRelin1 = evaluator.relinearize(cipherTextSxyaux1, relinKey);
    const cipherTextSxyauxRescale1 = evaluator.rescaleToNext(cipherTextSxyauxRelin1);
    cipherTextSxyaux1.delete();
    cipherTextSxyauxRelin1.delete();

    evaluator.add(cipherTextSxyauxRescale0, cipherTextSxyauxRescale1, cipherTextSxy);
    cipherTextSxyauxRescale0.delete();
    cipherTextSxyauxRescale1.delete();

    var cipherTextSxyaux = seal.CipherText();
    var cipherTextSxyauxRelin = seal.CipherText();
    for (let i=2; i<N; i++) {
        evaluator.multiply(storeYValues[i], storeXValues[i], cipherTextSxyaux);
        cipherTextSxyauxRelin = evaluator.relinearize(cipherTextSxyaux, relinKey);
        storeXYvalues[i] = evaluator.rescaleToNext(cipherTextSxyauxRelin);
    } 
    cipherTextSxyaux.delete();
    cipherTextSxyauxRelin.delete();

    for (let i=2; i<N; i++) {
        evaluator.add(storeXYvalues[i], cipherTextSxy, cipherTextSxy);
        storeXYvalues[i].delete();
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
    cipherTextSxxaux0.delete();
    cipherTextSxxauxRelin0.delete();

    evaluator.multiply(storeXValues[1], storeXValues[1], cipherTextSxxaux1);
    const cipherTextSxxauxRelin1 = evaluator.relinearize(cipherTextSxxaux1, relinKey);
    const cipherTextSxxauxRescale1 = evaluator.rescaleToNext(cipherTextSxxauxRelin1);
    cipherTextSxxaux1.delete();
    cipherTextSxxauxRelin1.delete();

    evaluator.add(cipherTextSxxauxRescale0, cipherTextSxxauxRescale1, cipherTextSxx);
    cipherTextSxxauxRescale0.delete();
    cipherTextSxxauxRescale1.delete();

    var cipherTextSxxaux = seal.CipherText();
    var cipherTextSxxauxRelin = seal.CipherText();
    for (let i=2; i<N; i++) {
        evaluator.multiply(storeXValues[i], storeXValues[i], cipherTextSxxaux);
        cipherTextSxxauxRelin = evaluator.relinearize(cipherTextSxxaux, relinKey);
        storeXXvalues[i] = evaluator.rescaleToNext(cipherTextSxxauxRelin);
    }
    cipherTextSxxaux.delete();
    cipherTextSxxauxRelin.delete();

    for (let i=2; i<N; i++) {
        evaluator.add(storeXXvalues[i], cipherTextSxx, cipherTextSxx);
        storeXXvalues[i].delete();
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
    const NPlaintext = encoder.encode(Float64Array.from({ length: encoder.slotCount }).fill(N), scale);

    // Compute mA = N*Sxy
    NPlaintext.setScale(cipherTextSxy.scale);
    const NPlaintextModSwitch = evaluator.plainModSwitchToNext(NPlaintext);
    let mA = seal.CipherText();
    evaluator.multiplyPlain(cipherTextSxy, NPlaintextModSwitch, mA);
    const mARelin = evaluator.relinearize(mA, relinKey);
    const mARescale = evaluator.rescaleToNext(mARelin);
    mA.delete();
    mARelin.delete();

    // Compute mB = Sx*Sy
    let mB = seal.CipherText();
    evaluator.multiply(cipherTextSx, cipherTextSy, mB);
    const mBRelin = evaluator.relinearize(mB, relinKey);
    const mBRescale = evaluator.rescaleToNext(mBRelin);
    mB.delete();
    mBRelin.delete();

    // Compute mAB = mA - mB
    let mAB = seal.CipherText();
    mBRescale.setScale(mARescale.scale);
    const mBRescaleModSwitch = evaluator.cipherModSwitchTo(mBRescale, mARescale.parmsId);
    evaluator.sub(mARescale, mBRescaleModSwitch, mAB);
    mARescale.delete();
    mBRescale.delete();
    mBRescaleModSwitch.delete();

    // Compute mC = N*Sxx
    let mC = seal.CipherText();
    evaluator.multiplyPlain(cipherTextSxx, NPlaintextModSwitch, mC);
    const mCRelin = evaluator.relinearize(mC, relinKey);
    const mCRescale = evaluator.rescaleToNext(mCRelin);
    NPlaintext.delete();
    NPlaintextModSwitch.delete();
    mC.delete();
    mCRelin.delete();

    // Compute mD = Sx*Sx
    let mD = seal.CipherText();
    evaluator.multiply(cipherTextSx, cipherTextSx, mD);
    const mDRelin = evaluator.relinearize(mD, relinKey);
    const mDRescale = evaluator.rescaleToNext(mDRelin);
    mD.delete();
    mDRelin.delete();

    // Compute mCD = mC - mD
    let mCD = seal.CipherText();
    mDRescale.setScale(mCRescale.scale);
    const mDRescaleModSwitch = evaluator.cipherModSwitchTo(mDRescale, mCRescale.parmsId);
    evaluator.sub(mCRescale, mDRescaleModSwitch, mCD);
    mDRescale.delete();
    mDRescaleModSwitch.delete();

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
    cipherTextSx.delete();
    cipherTextSy.delete();

    // Compute bA = Sy*Sxx
    let bA = seal.CipherText();
    evaluator.multiply(cipherTextSyRescaleModSwitch, cipherTextSxx, bA);
    const bARelin = evaluator.relinearize(bA, relinKey);
    const bARescale = evaluator.rescaleToNext(bARelin);
    bA.delete();
    bARelin.delete();
    cipherTextSxx.delete();
    cipherTextSyRescaleModSwitch.delete();

    // Compute bB = Sx*Sxy
    let bB = seal.CipherText();
    evaluator.multiply(cipherTextSxRescaleModSwitch, cipherTextSxy, bB);
    const bBRelin = evaluator.relinearize(bB, relinKey);
    const bBRescale = evaluator.rescaleToNext(bBRelin);
    bB.delete();
    bBRelin.delete();
    cipherTextSxy.delete();
    cipherTextSxRescaleModSwitch.delete();

    // Compute bAB = bA - bB
    let bAB = seal.CipherText();
    evaluator.sub(bARescale, bBRescale, bAB);
    bARescale.delete();
    bBRescale.delete();
    
    encoder.delete();
    publicKey.delete();
    encryptor.delete();
    relinKey.delete();
    evaluator.delete();

    /**************************************************
     * RETURN SLOPE AND CUT POINT NUMERATOR
     * AND DENOMINATOR
     **************************************************/
    const mABBase64 = mAB.save();
    mAB.delete();
    const bABBase64 = bAB.save();
    bAB.delete();
    const mCDBase64 = mCD.save();
    mCD.delete();

    res.json({numeratorSlope: mABBase64, numeratorCutPoint: bABBase64, denominator: mCDBase64});
})

/**************************************************
 * EXPORT
 **************************************************/
module.exports = router;