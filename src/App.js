import './App.css';
import axios from 'axios';
import React from "react";
import LoadingSpinner from './LoadingSpinner';
import {ReactComponent as PowerOnOff} from './res/powerOnOff.svg';
import { ReactComponent as Circle } from './res/circle.svg';

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
  const [galoisBase64Key, setGaloisBase64Key] = React.useState(null);

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

  const [fillCircleOne, setFillCircleOne] = React.useState('white');
  const [fillCircleTwo, setFillCircleTwo] = React.useState('white');
  const [fillCircleThree, setFillCircleThree] = React.useState('white');
  const [fillCircleOnePredict, setFillCircleOnePredict] = React.useState('white');
  const [fillCircleTwoPredict, setFillCircleTwoPredict] = React.useState('white');
  const [fillCircleThreePredict, setFillCircleThreePredict] = React.useState('white');

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
    * Uncomment the encryption security level with
    * the given bitSizes needed
    **************************************************/
    const schemeType = seal.SchemeType.ckks;
    const polyModulusDegree = 8192;
    const securityLevel = seal.SecurityLevel.tc128;
    const bitSizes = [60, 30, 30, 30, 60];
    const bitSize = 30;
    /* const securityLevel = seal.SecurityLevel.tc192;
    const bitSizes = [41, 21, 21, 21, 41];
    const bitSize = 21; */

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

      /**************************************************
       * HOMOMORPHIC OBJECTS INITIALIZATION
       **************************************************/
      let encoder = seal.CKKSEncoder(context);
      setEncoder(encoder);
      const keyGenerator = seal.KeyGenerator(context);
      const publicKey = keyGenerator.createPublicKey();
      const secretKey = keyGenerator.secretKey();
      const relinKey = keyGenerator.createRelinKeys();
      const galoisKey = keyGenerator.createGaloisKeys();
      let encryptor = seal.Encryptor(context, publicKey, secretKey);
      setEncryptor(encryptor);
      let decryptor = seal.Decryptor(context, secretKey);
      setDecryptor(decryptor);

      /**************************************************
       * SAVE KEYS TO BE SENT AS BASE64 STRINGS
       **************************************************/
      const relinBase64Key = relinKey.save();
      setRelinBase64Key(relinBase64Key);
      const galoisBase64Key = galoisKey.save();
      setGaloisBase64Key(galoisBase64Key);
      
      /**************************************************
       * TOGGLE VISIBILITY
       **************************************************/
      setDivDisabledParms(false);
      setCreatingParms(false);
      setTextColorDisabledParms('rgb(0,0,0)');
      setPowerOff(false);
    }
  }




  /**************************************************
   * COMPUTE PARAMETERS FOR LINEAR REGRESSION
   **************************************************/
  const callServer = async () => {
    // Inform client that encryption has begun
    setComputingParms(true);
    setServerAnswer(`Encriptando...`);
    setFillCircleOne('white');
    setFillCircleTwo('white');
    setFillCircleThree('white');

    /**************************************************
     * OBTAIN AXIS ARRAYS
     **************************************************/
    let arrayX = document.getElementById('valuesXId').value.split(',');
    let arrayY = document.getElementById('valuesYId').value.split(',');

    if (arrayX.length !== arrayY.length || arrayX.length<0) {
        setFillCircleOne('rgba(255, 0, 0, 0.9)');
        setComputingParms(false);
        setServerAnswer(`La longitud de ambos ejes debe ser la misma.`);
        return;
    }

    if (arrayX.length<3) {
      setFillCircleOne('rgba(255, 0, 0, 0.9)');
      setComputingParms(false);
      setServerAnswer(`Se requiere de la introducción de por lo menos 3 valores para ofrecer un ajuste fiable.`);
      return;
    }

    /**************************************************
     * STORE ARRAY VALUES ENCRYPTED
     **************************************************/

    const plainArrayX = encoder.encode(Float64Array.from(arrayX), scale);
    const plainArrayY = encoder.encode(Float64Array.from(arrayY), scale);
    const cipherArrayX = encryptor.encrypt(plainArrayX);
    const cipherArrayXBase64 = cipherArrayX.save();
    const cipherArrayY = encryptor.encrypt(plainArrayY);
    const cipherArrayYBase64 = cipherArrayY.save();
    const plainN = encoder.encode(Float64Array.from({ length: encoder.slotCount }).fill(arrayX.length), scale);
    const plainNBase64 = plainN.save();

    /**************************************************
     * AXIOS ASYNCHRONOUS PETITION
     **************************************************/
    var postData = {
      valuesX: cipherArrayXBase64,
      valuesY: cipherArrayYBase64,
      N: plainNBase64,
      parmsBase64: parmsBase64,
      relinBase64Key: relinBase64Key,
      galoisBase64Key: galoisBase64Key
    };
    
    let axiosConfig = {
      headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          "Access-Control-Allow-Origin": "*",
      }
    };

    // Inform client that the server is computing the data
    setServerAnswer(`Esperando respuesta del servidor...`);
    setFillCircleOne('rgba(0, 255, 0, 0.9)');

    await axios.post('http://localhost:3000/api/parms-linear-reg', postData, axiosConfig)
    .then(res => {
      // Inform client that the decryption has begun
      setServerAnswer(`Desencriptando...`);
      setFillCircleTwo('rgba(0, 255, 0, 0.9)');

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
      numeratorSlopeEncrypted.delete();
      const decryptedPlainTextNumeratorCP = decryptor.decrypt(numeratorCutPointEncrypted);
      numeratorCutPointEncrypted.delete();
      const decryptedPlainTextDenominator = decryptor.decrypt(denominatorEncrypted);
      denominatorEncrypted.delete();

      /**
       * Decode variables
       */
      const decodedArrayNumeratorSlope = encoder.decode(decryptedPlainTextNumeratorSlope);
      decryptedPlainTextNumeratorSlope.delete();
      const decodedArrayNumeratorCP = encoder.decode(decryptedPlainTextNumeratorCP);
      decryptedPlainTextNumeratorCP.delete();
      const decodedArrayDenominator = encoder.decode(decryptedPlainTextDenominator);
      decryptedPlainTextDenominator.delete();

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
      setFillCircleThree('rgba(0, 255, 0, 0.9)');

    }).catch(err => {
      setComputingParms(false);
      setFillCircleTwo('rgba(255, 0, 0, 0.9)');
      console.log(err.response.data)
    });
  }




  /**************************************************
   * COMPUTE PREDICTION
   **************************************************/
  const callServerPredict = async () => {
    // Inform client that encryption has begun
    setComputingPredict(true);
    setServerAnswerTwo(`Encriptando...`);
    setFillCircleOnePredict('white');
    setFillCircleTwoPredict('white');
    setFillCircleThreePredict('white');

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
    plainTextM.delete();
    cipherTextM.delete();
    // x
    const plainTextX = seal.PlainText();
    const sealArrayX = Float64Array.from([predictX]);
    encoder.encode(sealArrayX, scale, plainTextX);
    const cipherTextX = encryptor.encryptSymmetric(plainTextX);
    const cipherTextXBase64 = cipherTextX.save();
    plainTextX.delete();
    cipherTextX.delete();
    // b
    const plainTextB = seal.PlainText();
    const sealArrayB = Float64Array.from([b]);
    encoder.encode(sealArrayB, scale, plainTextB);
    const cipherTextB = encryptor.encryptSymmetric(plainTextB);
    const cipherTextBBase64 = cipherTextB.save();
    plainTextB.delete();
    cipherTextB.delete();

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
    setFillCircleOnePredict('rgba(0, 255, 0, 0.9)');

    await axios.post('http://localhost:3000/api/predict-linear-reg', postData, axiosConfig)
    .then(res => {
      // Inform client that the decryption has begun
      setServerAnswerTwo(`Desencriptando...`);
      setFillCircleTwoPredict('rgba(0, 255, 0, 0.9)');

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
      predictionEncrypted.delete();

      /**
       * Decode variables
       */
      const decodedArrayPrediction = encoder.decode(decryptedPlainTextPrediction);
      decryptedPlainTextPrediction.delete();

      /**
       * Compute slope and cut point in y axis
       */
      let y = decodedArrayPrediction[0];

      /**
       * Actualizar UI
       */
      setServerAnswerTwo(`y = ${y}`);
      setComputingPredict(false);
      setFillCircleThreePredict('rgba(0, 255, 0, 0.9)');

    }).catch(err => {
      setComputingPredict(false);
      setFillCircleTwoPredict('rgba(255, 0, 0, 0.9)');
      console.log(err.response.data)
    });

  }

  return (
    <div style={{display: 'flex', flexDirection: 'row'}}>
      <button onClick={initSEAL} className="btnInitSEAL">
        {creatingParms ? <LoadingSpinner/> : 
        (powerOff ? <PowerOnOff className='icon__off' fill='rgba(255, 0, 0, 0.9)'/> : 
        <PowerOnOff className='icon__on' fill='rgba(0, 255, 0, 0.9)'/>)}
      </button>
      <div className="App" style={{display: 'flex', flexDirection: 'column', alignItems: 'center'}}>
        <div style={{display: 'flex', flexDirection: 'row'}}>
          <div className="firstForm">
            <form style={{display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2%'}}>
              <h4 style={{color: textColorDisabledParms}}>Calcular parámetros para la recta de ajuste: pendiente (m) y punto de corte con el eje Y (b)</h4>
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
          <div className='show__timeline'>
            <ul className="timeline">
              <li>
                  <div className="timeline-badge">
                    <Circle fill={fillCircleOne} className='icon__circle'/>
                  </div>
                  <div className="timeline-panel">
                      <div className="timeline-heading">
                          <h4>Cliente</h4>
                      </div>
                      <div className="timeline-body">
                          <p>Encripta los ejes X e Y y los envía al servidor.</p>
                      </div>
                  </div>
              </li>
              <li className="timeline-inverted">
                  <div className="timeline-badge">
                    <Circle fill={fillCircleTwo} className='icon__circle'/>
                  </div>
                  <div className="timeline-panel">
                      <div className="timeline-heading">
                          <h4>Servidor</h4>
                      </div>
                      <div className="timeline-body">
                          <p>Calcula la pendiente y el punto de corte en el eje Y con los datos encriptados recibidos.
                            Los reenvía al cliente aun encriptados. No conoce la clave privada.
                          </p>
                      </div>
                  </div>
              </li>
              <li>
                  <div className="timeline-badge">
                    <Circle fill={fillCircleThree} className='icon__circle'/>
                  </div>
                  <div className="timeline-panel">
                      <div className="timeline-heading">
                          <h4>Cliente</h4>
                      </div>
                      <div className="timeline-body">
                          <p>Desencripta los parámetros recibidos con la clave privada y muestra la ecuación lineal.</p>
                      </div>
                  </div>
              </li>
              <li className="clearfix no-float"></li>
            </ul>
          </div>
        </div>
        <div style={{display: 'flex', flexDirection: 'row'}}>
          <div className="firstForm" style={{marginTop: '3%'}}>
            <form style={{display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2%'}}>
              <h4 style={{color: textColorDisabledPredict}}>Calcular predicción en el eje Y conocido el valor en el eje X</h4>
              <input type="text" className="inputFirstForm" name="predict" id="valuePredict" 
                placeholder='Insertar valor en X' disabled={divDisabled}/>
            </form>
            <button onClick={callServerPredict} className="btnFirstForm" disabled={divDisabled}>
              {computingPredict ? <LoadingSpinner/> : 'Enviar'}
            </button>
            <p>{serverAnswerTwo}</p>
          </div>
          <div className='show__timeline'>
            <ul className="timeline">
              <li>
                  <div className="timeline-badge">
                    <Circle fill={fillCircleOnePredict} className='icon__circle'/>
                  </div>
                  <div className="timeline-panel">
                      <div className="timeline-heading">
                          <h4>Cliente</h4>
                      </div>
                      <div className="timeline-body">
                          <p>Encripta la pendiente y el punto de corte obtenidos anteriormente junto con el valor en X para la predicción y los envía al servidor.</p>
                      </div>
                  </div>
              </li>
              <li className="timeline-inverted">
                  <div className="timeline-badge">
                    <Circle fill={fillCircleTwoPredict} className='icon__circle'/>
                  </div>
                  <div className="timeline-panel">
                      <div className="timeline-heading">
                          <h4>Servidor</h4>
                      </div>
                      <div className="timeline-body">
                          <p>Calcula la predicción con la ecuación 'y = mx + b' en el eje Y y la reenvía encriptada al cliente. No conoce la clave privada.
                          </p>
                      </div>
                  </div>
              </li>
              <li>
                  <div className="timeline-badge">
                    <Circle fill={fillCircleThreePredict} className='icon__circle'/>
                  </div>
                  <div className="timeline-panel">
                      <div className="timeline-heading">
                          <h4>Cliente</h4>
                      </div>
                      <div className="timeline-body">
                          <p>Desencripta la predicción obtenida y la muestra por pantalla.</p>
                      </div>
                  </div>
              </li>
              <li className="clearfix no-float"></li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
