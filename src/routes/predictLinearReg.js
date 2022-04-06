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
    const cipherTextBase64Predict = req.body.cipherTextBase64Predict;
    const cipherTextBase64M = req.body.cipherTextBase64M;
    const cipherTextBase64B = req.body.cipherTextBase64B;
    const parmsBase64 = req.body.parmsBase64;
    const relinBase64Key = req.body.relinBase64Key;
 
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
        seal.SecurityLevel.tc128 // Enforce a security level
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

    /**************************************************
     * FORMULA TO BE COMPUTED
     * 
     * y = mx + b
     **************************************************/
    // CipherTexts
    var cipherTextm = seal.CipherText();
    cipherTextm.load(context, cipherTextBase64M);
    var cipherTextx = seal.CipherText();
    cipherTextx.load(context, cipherTextBase64Predict);
    var cipherTextb = seal.CipherText();
    cipherTextb.load(context, cipherTextBase64B);

    // Compute aux = m*x
    var cipherTextaux = seal.CipherText();
    cipherTextaux = evaluator.multiply(cipherTextm, cipherTextx);
    const cipherTextauxRelin = evaluator.relinearize(cipherTextaux, relinKey);
    const cipherTextauxRescale = evaluator.rescaleToNext(cipherTextauxRelin);
    cipherTextaux.delete();
    cipherTextauxRelin.delete();
    cipherTextm.delete();
    cipherTextx.delete();

    // Rescale and mod switch b to match mx
    cipherTextb.setScale(cipherTextauxRescale.scale);
    const cipherTextbModSwitch = evaluator.cipherModSwitchTo(cipherTextb, cipherTextauxRescale.parmsId);
    cipherTextb.delete();

    // Compute prediction
    let cipherTextPrediction = seal.CipherText();
    evaluator.add(cipherTextauxRescale, cipherTextbModSwitch, cipherTextPrediction);
    cipherTextauxRescale.delete();
    cipherTextbModSwitch.delete();

    relinKey.delete();
    evaluator.delete();

    /**************************************************
     * RETURN PREDICTION
     **************************************************/
    const cipherTextBase64Prediction = cipherTextPrediction.save();
    cipherTextPrediction.delete();
 
    res.json({yPrediction: cipherTextBase64Prediction});

});

/**************************************************
 * EXPORT
 **************************************************/
 module.exports = router;