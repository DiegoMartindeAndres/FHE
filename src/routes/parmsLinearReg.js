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
    const NBase64 = req.body.N;
    const parmsBase64 = req.body.parmsBase64;
    const relinBase64Key = req.body.relinBase64Key;
    const galoisBase64Key = req.body.galoisBase64Key;

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
    const context = seal.Context(
        parms, // Encryption Parameters
        true, // ExpandModChain
        // Enforce a security level
        seal.SecurityLevel.tc128
        //seal.SecurityLevel.tc192
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
    const relinKey = seal.RelinKeys();
    relinKey.load(context, relinBase64Key);
    const evaluator = seal.Evaluator(context);
    const galoisKey = seal.GaloisKeys();
    galoisKey.load(context, galoisBase64Key);
 
     /**************************************************
     * BASE64CIPHERTEXTS TO CIPHERTEXTS
     **************************************************/
    var cipherTextXaxis = seal.CipherText();
    cipherTextXaxis.load(context, arrayX);
    var cipherTextYaxis = seal.CipherText();
    cipherTextYaxis.load(context, arrayY);
    var N = seal.PlainText();
    N.load(context, NBase64);
    

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
    const Σx = evaluator.sumElements(cipherTextXaxis, galoisKey, seal.SchemeType.ckks);

    /**************************************************
     * COMPUTE Sy
     * Sy = sum(y[i])
     * The sum of all the values in the Y array
     **************************************************/
    const Σy = evaluator.sumElements(cipherTextYaxis, galoisKey, seal.SchemeType.ckks);

    /**************************************************
     * COMPUTE Sxy
     * Sxy = sum(x[i]*y[i])
     * The sum of all the products of the values in 
     * the X array times the ones in the Y array
     **************************************************/
    const xy = evaluator.multiply(cipherTextXaxis, cipherTextYaxis);
    evaluator.relinearize(xy, relinKey, xy);
    evaluator.cipherModSwitchToNext(xy, xy);
    const Σxy = evaluator.sumElements(xy, galoisKey, seal.SchemeType.ckks);

    /**************************************************
     * COMPUTE Sxx
     * Sxx = sum(x[i]*x[i])
     * The sum of all the products of the values in 
     * the X array times themselves
     **************************************************/
    const xx = evaluator.square(cipherTextXaxis);
    evaluator.relinearize(xx, relinKey, xx);
    evaluator.cipherModSwitchToNext(xx, xx);
    const Σxx = evaluator.sumElements(xx, galoisKey, seal.SchemeType.ckks);

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
    // Compute mA = N*Sxy
    const mod_N = evaluator.plainModSwitchToNext(N);
    const mA = evaluator.multiplyPlain(Σxy, mod_N);
    evaluator.rescaleToNext(mA, mA);

    // Compute mB = Sx*Sy
    const mB = evaluator.multiply(Σx, Σy);
    evaluator.relinearize(mB, relinKey, mB);
    // Go to next mod without changing scale so that we match mA parms
    evaluator.cipherModSwitchToNext(mB, mB);
    evaluator.cipherModSwitchToNext(mB, mB);

    // Compute mAB = mA - mB
    // Scales are very close in value, set to match so that we can subtract. This introduces a small amount of error.
    mA.setScale(mB.scale);
    const mAB = evaluator.sub(mA, mB);

    // Compute mC = N*Sxx
    const mC = evaluator.multiplyPlain(Σxx, mod_N);
    evaluator.rescaleToNext(mC, mC);

    // Compute mD = Sx*Sx
    const mD = evaluator.square(Σx);
    evaluator.relinearize(mD, relinKey, mD);
    evaluator.cipherModSwitchToNext(mD, mD);
    // Go to next mod without changing scale so that we match mC parms
    evaluator.cipherModSwitchToNext(mD, mD);

    // Compute mCD = mC - mD
    // Scales are very close in value, set to match so that we can subtract. This introduces a small amount of error.
    mC.setScale(mD.scale);
    const mCD = evaluator.sub(mC, mD);

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
    // Compute bA = Sy*Sxx
    const ba_Σy = evaluator.cipherModSwitchToNext(Σy);
    const bA = evaluator.multiply(ba_Σy, Σxx);
    evaluator.relinearize(bA, relinKey, bA);
    evaluator.rescaleToNext(bA, bA);

    // Compute bB = Sx*Sxy
    const bb_Σx = evaluator.cipherModSwitchToNext(Σx);
    const bB = evaluator.multiply(bb_Σx, Σxy);
    evaluator.relinearize(bB, relinKey, bB);
    evaluator.rescaleToNext(bB, bB);

    // Compute bAB = bA - bB
    const bAB = evaluator.sub(bA, bB);
    
    relinKey.delete();
    evaluator.delete();
    galoisKey.delete();

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