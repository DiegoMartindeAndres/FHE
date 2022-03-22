const {Router} = require('express');
const router = Router();
const _ = require('underscore');
//const {learnLinear} = require('../linearReg');
const tf = require('@tensorflow/tfjs-node');

// Routes
router.get('/', async (req, res) => { // http://localhost:3000/api/linear
    let prediction = await learnLinear([1, 2, 3, 4, 5], [10,20,30,40,50]);
    res.send(`Prediction: ${prediction}`);
});


async function learnLinear(arrayX, arrayY) {
    // Raw data
    const trainData = {
        xs: arrayX,
        ys: arrayY
    };

    // Create tensors
    const trainTensors = {
        xs: tf.tensor2d(trainData.xs, [trainData.xs.length, 1]),
        ys: tf.tensor2d(trainData.ys, [trainData.ys.length, 1])
    };

    // Linear regression model
    const model = tf.sequential();
    // Add dense layer of one dimension (linear)
    model.add(tf.layers.dense({units: 1, inputShape: [1]}));
    
    // Compile model -> configure training options
    model.compile({loss: 'meanSquaredError', optimizer: 'sgd'});

    // Linear regression model with 10 repetitions
    await model.fit(trainTensors.xs,
        trainTensors.ys,
        {epochs: 100});

    // Predict
    const output = model.predict(tf.tensor2d([6],[1,1]));
    const prediction = Array.from(output.dataSync())[0];
    return prediction;
}

// Export
module.exports = router;