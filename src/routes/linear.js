const {Router} = require('express');
const router = Router();
const _ = require('underscore');

// Routes
router.get('/', async (req, res) => { // http://localhost:3000/api/linear
    let prediction = leastSquaresMethod([1, 2, 3, 5, 6, 8, 9, 10], [1.5, 2, 4, 4.6, 4.7, 8.5, 8.8, 9]);
    res.send(`Prediction: ${prediction}`);
});

function leastSquaresMethod(arrayX, arrayY) {
    // Raw data
    const trainData = {
        xs: arrayX,
        ys: arrayY
    };

    /**
     * Least Squares Method operations
     */
    let N = trainData.xs.length; // Total number of values to be evaluated
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

    /**
     * Linear correlation coefficient
     * If r is too low, linear regression is not a good option for this dataset
     */
    let r = (N*Sxy-Sx*Sy)/(Math.sqrt(N*Sxx-Sx*Sx)*Math.sqrt(N*Syy-Sy*Sy));
    console.log(`Linear correlation coefficient r: ${r}`);

    /**
     * Slope
     */
    let m = (N*Sxy-Sx*Sy)/(N*Sxx-Sx*Sx);

    /**
     * Cut point Y axis
     */
    let b = (Sy*Sxx-Sx*Sxy)/(N*Sxx-Sx*Sx);

    /**
     * Error
     */
    let beta_sq = 0;
    for (let i=0; i<N; i++) {
        beta_sq += Math.pow(b + m*trainData.xs[i] - trainData.ys[i], 2);
    }

    let e_m = Math.sqrt((N/(N*Sxx-Sx*Sx))*(beta_sq/(N-2)));
    console.log(`Slope error: ${e_m}`);

    let e_b = Math.sqrt((Sxx/(N*Sxx-Sx*Sx))*(beta_sq/(N-2)));
    console.log(`Y axis cut point error: ${e_b}`);

    /**
     * Final equation
     * y = mx + b
     * y = (m +- e_m)x + (b +- e_b)
     */
    let x = 11;
    let prediction = m*x + b;
    return prediction;
}

// Export
module.exports = router;