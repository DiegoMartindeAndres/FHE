import './App.css';
import axios from 'axios';
import React from "react";
import LoadingSpinner from './LoadingSpinner';
import {ReactComponent as PowerOnOff} from './res/powerOnOff.svg';

const SEAL = require('node-seal');

function App() {
  // UseState for homomorphic variables
  const [seal, setSeal] = React.useState(null);
  const [parmsBase64, setParmsBase64] = React.useState(null);
  const [context, setContext] = React.useState(null);
  const [scale, setScale] = React.useState(0);

  const [encoder, setEncoder] = React.useState(null);
  const [encryptor, setEncryptor] = React.useState(null);
  const [decryptor, setDecryptor] = React.useState(null);

  const [publicBase64Key, setPublicBase64Key] = React.useState(null);
  const [relinBase64Key, setRelinBase64Key] = React.useState(null);

  // Linear regression variables
  const [m, setM] = React.useState(0);
  const [b, setB] = React.useState(0);

  // UseState for displaying server answers
  const [serverAnswer, setServerAnswer] = React.useState(null);
  const [serverAnswerTwo, setServerAnswerTwo] = React.useState(null);

  // UseState for visibility
  const [powerOff, setPowerOff] = React.useState(true);
  const [creatingParms, setCreatingParms] = React.useState(false);
  const [computingParms, setComputingParms] = React.useState(false);
  const [computingPredict, setComputingPredict] = React.useState(false);
  const [divDisabledParms, setDivDisabledParms] = React.useState(true);
  const [divDisabled, setDivDisabled] = React.useState(true);
  const [textColorDisabledParms, setTextColorDisabledParms] = React.useState('rgb(150, 150, 150)');
  const [textColorDisabledPredict, setTextColorDisabledPredict] = React.useState('rgb(150, 150, 150)');

  /**************************************************
   * INITIALIZE SEAL VARIABLES
   **************************************************/
  async function initSEAL() {
    /**************************************************
     * INIT SEAL
     **************************************************/
    setCreatingParms(true);
    let seal = await SEAL();
    setSeal(seal);

    /**************************************************
    * SCHEME PARAMETERS
    **************************************************/
    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 8192;
    const bitSizes = [50, 30, 30, 30, 50];
    const bitSize = 30;

    let scale = Math.pow(2.0, bitSize);
    setScale(scale);
    
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
    * SAVE PARMS INTO THE STREAM
    **************************************************/
    let parmsBase64 = parms.save();
    setParmsBase64(parmsBase64);
    
    /**************************************************
    * CREATE CONTEXT
    **************************************************/
    let context = seal.Context(
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
    } else {
      setContext(context);
    }

    /**************************************************
     * HOMOMORPHIC OBJECTS INITIALIZATION
     **************************************************/
    let encoder = seal.CKKSEncoder(context);
    setEncoder(encoder);
    const keyGenerator = seal.KeyGenerator(context);
    const publicKey = keyGenerator.createPublicKey();
    const secretKey = keyGenerator.secretKey();
    const relinKey = keyGenerator.createRelinKeys();
    let encryptor = seal.Encryptor(context, publicKey, secretKey);
    setEncryptor(encryptor);
    let decryptor = seal.Decryptor(context, secretKey);
    setDecryptor(decryptor);

    /**************************************************
     * SAVE KEYS TO BE SENT AS BASE64 STRINGS
     **************************************************/
    const relinBase64Key = relinKey.save();
    setRelinBase64Key(relinBase64Key);
    const publicBase64Key = publicKey.save();
    setPublicBase64Key(publicBase64Key);
    
    /**************************************************
     * TOGGLE VISIBILITY
     **************************************************/
    setDivDisabledParms(false);
    setCreatingParms(false);
    setTextColorDisabledParms('rgb(0,0,0)');
    setPowerOff(false);
  }




  /**************************************************
   * COMPUTE PARAMETERS FOR LINEAR REGRESSION
   **************************************************/
  const callServer = async () => {
    // Inform client that encryption has begun
    setComputingParms(true);
    setServerAnswer(`Encriptando...`);

    /**************************************************
     * OBTAIN AXIS ARRAYS
     **************************************************/
    let arrayX = document.getElementById('valuesXId').value.split(',');
    let arrayY = document.getElementById('valuesYId').value.split(',');
    let N = arrayX.length;

    if (arrayX.length !== N ||
      arrayY.length !== N ||
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
    let storeXValues = []; // Array of X axis ciphertexts in base 64
    for (let i=0; i<N; i++) {
        const plainTextX = seal.PlainText();
        const sealArrayX = Float64Array.from([arrayX[i]]);
        encoder.encode(sealArrayX, scale, plainTextX);
        const cipherTextX = encryptor.encryptSymmetric(plainTextX);
        const cipherTextXBase64 = cipherTextX.save();
        storeXValues[i] = cipherTextXBase64;
    }

    let storeYValues = []; // Array of Y axis ciphertexts in base 64
    for (let i=0; i<N; i++) {
        const plainTextY = seal.PlainText();
        const sealArrayY = Float64Array.from([arrayY[i]]);
        encoder.encode(sealArrayY, scale, plainTextY);
        const cipherTextY = encryptor.encryptSymmetric(plainTextY);
        const cipherTextYBase64 = cipherTextY.save();
        storeYValues[i] = cipherTextYBase64;
    }

    /**************************************************
     * AXIOS ASYNCHRONOUS PETITION
     **************************************************/
    var postData = {
      valuesX: storeXValues,
      valuesY: storeYValues,
      parmsBase64: parmsBase64,
      scale: scale,
      relinBase64Key: relinBase64Key,
      publicBase64Key: publicBase64Key
    };
    
    let axiosConfig = {
      headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          "Access-Control-Allow-Origin": "*",
      }
    };

    // Inform client that the server is computing the data
    setServerAnswer(`Esperando respuesta del servidor...`);

    await axios.post('http://localhost:3000/api/parms-linear-reg', postData, axiosConfig)
    .then(res => {
      // Inform client that the decryption has begun
      setServerAnswer(`Desencriptando...`);

      /**
       * The format of the JSON to be received is the following:
       * {numeratorSlope, numeratorCutPoint, denominator}
       */
      const numeratorSlopeEncrypted = seal.CipherText();
      numeratorSlopeEncrypted.load(context, res.data.numeratorSlope);
      const numeratorCutPointEncrypted = seal.CipherText();
      numeratorCutPointEncrypted.load(context, res.data.numeratorCutPoint);
      const denominatorEncrypted = seal.CipherText();
      denominatorEncrypted.load(context, res.data.denominator);
      
      /**
       * Decrypt variables
       */
      const decryptedPlainTextNumeratorSlope = decryptor.decrypt(numeratorSlopeEncrypted);
      const decryptedPlainTextNumeratorCP = decryptor.decrypt(numeratorCutPointEncrypted);
      const decryptedPlainTextDenominator = decryptor.decrypt(denominatorEncrypted);

      /**
       * Decode variables
       */
      const decodedArrayNumeratorSlope = encoder.decode(decryptedPlainTextNumeratorSlope);
      const decodedArrayNumeratorCP = encoder.decode(decryptedPlainTextNumeratorCP);
      const decodedArrayDenominator = encoder.decode(decryptedPlainTextDenominator);

      /**
       * Compute slope and cut point in y axis
       */
      let m = decodedArrayNumeratorSlope[0] / decodedArrayDenominator[0];
      setM(m);
      let b = decodedArrayNumeratorCP[0] / decodedArrayDenominator[0];
      setB(b);

      /**
       * Actualizar UI
       */
      setServerAnswer(
        b>0 ? `y = mx + b = ${m}x + ${b}`
        : `y = mx + b = ${m}x - ${Math.abs(b)}`
      );
      setDivDisabled(false);
      setTextColorDisabledPredict('rgb(0,0,0)');
      setComputingParms(false);

    }).catch(err => console.log(err.response.data));
  }




  /**************************************************
   * COMPUTE PREDICTION
   **************************************************/
  const callServerPredict = async () => {
    // Inform client that encryption has begun
    setComputingPredict(true);
    setServerAnswerTwo(`Encriptando...`);

    /**************************************************
     * OBTAIN X VALUE FOR PREDICTION
     **************************************************/
    let predictX = document.getElementById('valuePredict').value.split(',');

    /**************************************************
     * ENCRYPT DATA TO PREDICT y = mx + b
     **************************************************/
    // m
    const plainTextM = seal.PlainText();
    const sealArrayM = Float64Array.from([m]);
    encoder.encode(sealArrayM, scale, plainTextM);
    const cipherTextM = encryptor.encryptSymmetric(plainTextM);
    const cipherTextMBase64 = cipherTextM.save();
    // x
    const plainTextX = seal.PlainText();
    const sealArrayX = Float64Array.from([predictX]);
    encoder.encode(sealArrayX, scale, plainTextX);
    const cipherTextX = encryptor.encryptSymmetric(plainTextX);
    const cipherTextXBase64 = cipherTextX.save();
    // b
    const plainTextB = seal.PlainText();
    const sealArrayB = Float64Array.from([b]);
    encoder.encode(sealArrayB, scale, plainTextB);
    const cipherTextB = encryptor.encryptSymmetric(plainTextB);
    const cipherTextBBase64 = cipherTextB.save();

    /**************************************************
     * AXIOS ASYNCHRONOUS PETITION
     **************************************************/
     var postData = {
      cipherTextBase64Predict: cipherTextXBase64,
      cipherTextBase64M: cipherTextMBase64,
      cipherTextBase64B: cipherTextBBase64,
      parmsBase64: parmsBase64,
      relinBase64Key: relinBase64Key
    };
    
    let axiosConfig = {
      headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          "Access-Control-Allow-Origin": "*",
      }
    };

    // Inform client that the server is computing the data
    setServerAnswerTwo(`Esperando respuesta del servidor...`);

    await axios.post('http://localhost:3000/api/predict-linear-reg', postData, axiosConfig)
    .then(res => {
      // Inform client that the decryption has begun
      setServerAnswerTwo(`Desencriptando...`);

      /**
       * The format of the JSON to be received is the following:
       * {yPrediction}
       */
      const predictionEncrypted = seal.CipherText();
      predictionEncrypted.load(context, res.data.yPrediction);
      
      /**
       * Decrypt variables
       */
      const decryptedPlainTextPrediction = decryptor.decrypt(predictionEncrypted);

      /**
       * Decode variables
       */
      const decodedArrayPrediction = encoder.decode(decryptedPlainTextPrediction);

      /**
       * Compute slope and cut point in y axis
       */
      let y = decodedArrayPrediction[0];

      /**
       * Actualizar UI
       */
      setServerAnswerTwo(`y = ${y}`);
      setComputingPredict(false);

    }).catch(err => console.log(err.response.data));

  }

  return (
    <div className="App" style={{display: 'flex', flexDirection: 'column', alignItems: 'center'}}>
      <button onClick={initSEAL} className="btnInitSEAL">
        {creatingParms ? <LoadingSpinner/> : 
        (powerOff ? <PowerOnOff className='icon__off' fill='rgba(255, 0, 0, 0.9)'/> : 
        <PowerOnOff className='icon__on' fill='rgba(0, 255, 0, 0.9)'/>)}
      </button>
      <div className="firstForm">
        <form style={{display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2%'}}>
          <h4 style={{color: textColorDisabledParms}}>Calcular parámetros para la regresión lineal,</h4>
          <input type="text" className="inputFirstForm" name="X axis" id="valuesXId" 
          placeholder='Insertar valores en X' disabled={divDisabledParms}/>
          <input type="text" className="inputFirstForm" name="Y axis" id="valuesYId" 
          placeholder='Insertar valores en Y' disabled={divDisabledParms}/>
        </form>
        <button onClick={callServer} className="btnFirstForm" disabled={divDisabledParms}>
            {computingParms ? <LoadingSpinner/> : 'Enviar'}
        </button>
        <p>{serverAnswer}</p>
      </div>
      <div className="firstForm" style={{marginTop: '3%'}}>
        <form style={{display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2%'}}>
          <h4 style={{color: textColorDisabledPredict}}>Calcular predicción,</h4>
          <input type="text" className="inputFirstForm" name="predict" id="valuePredict" 
            placeholder='Insertar valor en X' disabled={divDisabled}/>
        </form>
        <button onClick={callServerPredict} className="btnFirstForm" disabled={divDisabled}>
          {computingPredict ? <LoadingSpinner/> : 'Enviar'}
        </button>
        <p>{serverAnswerTwo}</p>
      </div>
    </div>
  );
}

export default App;
