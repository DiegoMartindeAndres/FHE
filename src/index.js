const express = require('express');
const app = express();
const morgan = require('morgan');
var bodyParser = require('body-parser');

// Settings
app.set('PORT', process.env.PORT || 3000); // The cloud's defined port || predefined port 3000
app.set('json spaces', 2); // JSON format

// Middlewares
app.use(morgan('dev')); // Obtain HTTP requests sent to the server
app.use(express.urlencoded({extended: false}));
app.use(express.json()); // Server understands JSON format
app.use(bodyParser.json({limit: '1000mb', extended: true}));
app.use(bodyParser.urlencoded({limit: '1000mb', extended: true}));
app.use(express.json({limit: '1000mb'}));
app.use(express.urlencoded({limit: '1000mb'}));

// Routes
app.use('/api/sumbfv', require('./routes/sumbfv.js'));
app.use('/api/sumckks', require('./routes/sumckks.js'));
app.use('/api/parms-linear', require('./routes/parmsLinear.js'));
app.use('/api/compute-linear', require('./routes/computeLinear.js'));
app.use('/api/encode', require('./routes/encode.js'));
app.use('/api/operate', require('./routes/operate.js'));

// Starting server -> npm run dev
app.listen(app.get('PORT'), () => {console.log(`Server on port ${app.get('PORT')}`)});