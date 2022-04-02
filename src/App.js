import './App.css';
import axios from 'axios';
import React from "react";
import LoadingSpinner from './LoadingSpinner';

const SEAL = require('node-seal');

function App() {
  // UseState for homomorphic variables
  const [seal, setSeal] = React.useState(null);
  const [context, setContext] = React.useState(null);
  const [scale, setScale] = React.useState(0);

  const [encoder, setEncoder] = React.useState(null);
  const [publicKey, setPublicKey] = React.useState(null);
  const [relinKey, setRelinKey] = React.useState(null);
  const [encryptor, setEncryptor] = React.useState(null);
  const [decryptor, setDecryptor] = React.useState(null);

  // UseState for displaying server answers
  const [serverAnswer, setServerAnswer] = React.useState(null);
  const [serverAnswerTwo, setServerAnswerTwo] = React.useState(null);

  // UseState for visibility
  const [creatingParms, setCreatingParms] = React.useState(false);
  const [divDisabledParms, setDivDisabledParms] = React.useState(true);
  const [divDisabled, setDivDisabled] = React.useState(true);

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
    let publicKey = keyGenerator.createPublicKey();
    setPublicKey(publicKey);
    const secretKey = keyGenerator.secretKey();
    let relinKey = keyGenerator.createRelinKeys();
    setRelinKey(relinKey);
    let encryptor = seal.Encryptor(context, publicKey, secretKey);
    setEncryptor(encryptor);
    let decryptor = seal.Decryptor(context, secretKey);
    setDecryptor(decryptor);
    
    /**************************************************
     * TOGGLE VISIBILITY
     **************************************************/
    setDivDisabledParms(false);
    setCreatingParms(false);
  }


  

  const callServer = async () => {
    // Inform client that encryption has begun
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
     * SAVE KEYS TO BE SENT AS BASE64 STRINGS
     **************************************************/
    const relinBase64Key = relinKey.save();
    const publicBase64Key = publicKey.save();

    /**************************************************
     * AXIOS ASYNCHRONOUS PETITION
     **************************************************/
    var postData = {
      valuesX: storeXValues,
      valuesY: storeYValues,
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

    await axios.post('http://localhost:3000/api/operate', postData, axiosConfig)
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
      const m = decodedArrayNumeratorSlope[0] / decodedArrayDenominator[0];
      const b = decodedArrayNumeratorCP[0] / decodedArrayDenominator[0];

      console.log('m', m);
      console.log('b', b);

      setServerAnswer(`y = mx + b = ${m}x + ${b}`);
      setDivDisabled(false);

    }).catch(err => console.log(err.response.data));
  }

  const callServerPredict = async () => {
    // Inform client that encryption has begun
    setServerAnswerTwo(`Encriptando...`);
  }

  return (
    <div className="App" style={{display: 'flex', flexDirection: 'column', alignItems: 'center'}}>
      <button onClick={initSEAL} className="btnInitSEAL">
          {creatingParms ? <LoadingSpinner/> : 'Init SEAL'}
      </button>
      <div className="firstForm">
        <form style={{display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2%'}}>
          <h4>Calcular parámetros para la regresión lineal,</h4>
          <input type="text" className="inputFirstForm" name="X axis" id="valuesXId" 
          placeholder='Insertar valores en X' disabled={divDisabledParms}/>
          <input type="text" className="inputFirstForm" name="Y axis" id="valuesYId" 
          placeholder='Insertar valores en Y' disabled={divDisabledParms}/>
        </form>
        <button onClick={callServer} className="btnFirstForm" disabled={divDisabledParms}>
            Enviar
        </button>
        <p>{serverAnswer}</p>
      </div>
      <div className="firstForm" style={{marginTop: '3%'}}>
        <form style={{display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2%'}}>
          <h4>Calcular predicción,</h4>
          <input type="text" className="inputFirstForm" name="predict" id="valuePredict" 
            placeholder='Insertar valor en X' disabled={divDisabled}/>
        </form>
        <button onClick={callServerPredict} className="btnFirstForm" disabled={divDisabled}>
            Enviar
        </button>
        <p>{serverAnswerTwo}</p>
      </div>
    </div>
  );
}

export default App;
