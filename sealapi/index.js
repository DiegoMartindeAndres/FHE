const express = require('express');
const app = express();
const morgan = require('morgan');
var cors = require('cors');

const connectDB = require('./src/database/connection');

// Settings
app.set('PORT', process.env.PORT || 3000); // The cloud's defined port || predefined port 3000
app.set('json spaces', 2); // JSON format

// Middlewares
app.use(morgan('dev')); // Obtain HTTP requests sent to the server
connectDB();
app.use(cors());
app.use(express.urlencoded({extended: false}));
app.use(express.json({limit: '50mb'}));
app.use(express.urlencoded({limit: '50mb'}));
app.use(express.json()); // Server understands JSON format  

// Routes
app.use('/api/parms-linear-reg', require('./src/routes/parmsLinearReg.js'));
app.use('/api/predict-linear-reg', require('./src/routes/predictLinearReg.js'));
app.use('/api/patients', require('./src/routes/patients.js'));
app.use('/api/avgweight', require('./src/routes/avgweight.js'))

// Starting server -> npm run dev
app.listen(app.get('PORT'), () => {console.log(`Server on port ${app.get('PORT')}`)});