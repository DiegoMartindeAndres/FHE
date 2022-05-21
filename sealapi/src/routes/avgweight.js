const {Router} = require('express');
const router = Router();
var Userdb = require('../model/model');

router.get('/', async (req, res) => {
    Userdb.find()
    .then(async users => {
        // SEAL parameters initialization
        const SEAL = require('node-seal');
        const seal = await SEAL();

        // Encryption Parameters
        const parms = seal.EncryptionParameters();
        parms.load(users[0].parms);
        const context = seal.Context(
            parms, // Encryption Parameters
            true, // ExpandModChain
            seal.SecurityLevel.tc128 // Enforce a security level
        );
        if (!context.parametersSet()) {
            throw new Error(
            'Could not set the parameters in the given context. Please try different encryption parameters.'
            )
        }

        // Homomorphic evaluator
        const evaluator = seal.Evaluator(context);

        // Iterate through the json
        let storeWeightValues = [];
        for (let i=0; i<users.length; i++) {
            let user = users[i];
            const uploadedCipherText = seal.CipherText();
            uploadedCipherText.load(context, user.weight);
            storeWeightValues[i] = uploadedCipherText;
        }
        var cipherTextSweight = evaluator.add(storeWeightValues[0], storeWeightValues[1]);
        for (let i=2; i<users.length; i++) {
            evaluator.add(storeWeightValues[i], cipherTextSweight, cipherTextSweight);
        }
        const cipherTextSweightBase64 = cipherTextSweight.save();
        res.json({encryptedSum: cipherTextSweightBase64, numElements: users.length, parms: users[0].parms});
    })
    .catch(err => {
        res.status(500).send({ message : err.message || "Error Occurred while retriving user information" })
    })
})

module.exports = router;