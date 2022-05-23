import axios from 'axios';
import React from "react";
import Swal from 'sweetalert2';
import '../style/App.css';
import '../style/pageone.css';
import LoadingSpinner from './LoadingSpinner';
import { ReactComponent as Circle } from '../res/circle.svg';
import { ReactComponent as PowerOnOff } from '../res/powerOnOff.svg';

const SEAL = require('node-seal');

function PageOne() {
    // UseState for homomorphic variables
  const [seal, setSeal] = React.useState(null);
  const [parmsBase64, setParmsBase64] = React.useState(null);
  const [context, setContext] = React.useState(null);
  const [scale, setScale] = React.useState(0);
  const [sendSecLevel, setSendSecLevel] = React.useState(null);

  const [encoder, setEncoder] = React.useState(null);
  const [encryptor, setEncryptor] = React.useState(null);
  const [decryptor, setDecryptor] = React.useState(null);

  const [publicBase64Key, setPublicBase64Key] = React.useState(null);
  const [relinBase64Key, setRelinBase64Key] = React.useState(null);

  // Linear regression variables
  const [m, setM] = React.useState(0);
  const [b, setB] = React.useState(0);

  // UseState for displaying server answers
  const [encryptedNumSlope, setEncryptedNumSlope] = React.useState(null);
  const [encryptedNumCP, setEncryptedNumCP] = React.useState(null);
  const [encryptedDen, setEncryptedDen] = React.useState(null);
  const [serverAnswer, setServerAnswer] = React.useState(null);
  const [encryptedPrediction, setEncryptedPrediction] = React.useState(null);
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
    const { value: secLevel } = await Swal.fire({
      title: 'Escoja el nivel de seguridad deseado:',
      text: 'Los siguientes niveles de seguridad se presentan de menor a mayor. Tenga en cuenta que cuanta mas seguridad escoja, mayor será la latencia.',
      input: 'select',
      inputOptions: {
        tc128: 'tc128',
        tc192: 'tc192',
        tc256: 'tc256'
      },
      inputPlaceholder: 'Nivel',
      icon: 'question',
      showCancelButton: true,
      confirmButtonColor: 'rgb(0, 200, 0)',
      reverseButtons: true,
      inputValidator: (value) => {
        return new Promise((resolve) => {
          if (value === '') {
            resolve('Debe escoger un nivel de seguridad.');
          } else {
            resolve();
          }
        })
      }
    })
    
    if (secLevel) {
      Swal.fire(
        `Nivel de seguridad seleccionado: ${secLevel}`,
        'Pulse OK para generar el esquema de encriptado.',
        'success'
      ).then(async () => {
        // Init SEAL
        setCreatingParms(true);
        let seal = await SEAL();
        setSeal(seal);

        // Scheme parameters
        setSendSecLevel(secLevel);
        const schemeType = seal.SchemeType.ckks;
        var polyModulusDegree = null;
        var securityLevel = null;
        var bitSizes = null;
        var bitSize = null;
        if (secLevel === 'tc128') {
          polyModulusDegree = 8192;
          securityLevel = seal.SecurityLevel.tc128;
          bitSizes = [59, 43, 43, 59];
          bitSize = 43;
        } else if (secLevel === 'tc192') {
          polyModulusDegree = 16384;
          securityLevel = seal.SecurityLevel.tc192;
          bitSizes = [60, 47, 47, 60];
          bitSize = 47;
        } else {
          polyModulusDegree = 16384;
          securityLevel = seal.SecurityLevel.tc256;
          bitSizes = [60, 47, 47, 60];
          bitSize = 47;
        }

        let scale = Math.pow(2.0, bitSize);
        setScale(scale);
        
        const parms = seal.EncryptionParameters(schemeType);
        
        // Polynomial modulus
        parms.setPolyModulusDegree(polyModulusDegree);
        
        // Coefficient modulus 
        parms.setCoeffModulus(
            seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
        );

        // Save parameters into the stream
        let parmsBase64 = parms.save();
        setParmsBase64(parmsBase64);
        
        // Create context
        let context = seal.Context(
            parms, // Encryption Parameters
            true, // ExpandModChain
            securityLevel // Enforce a security level
        );
        
        // Check correctness and return context
        if (!context.parametersSet()) {
            console.log('Could not set the parameters in the given context. Please try different encryption parameters.');
        } else {
          setContext(context);

          // Init homomorphic objects
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

          // Save Keys as Base64
          const relinBase64Key = relinKey.save();
          setRelinBase64Key(relinBase64Key);
          const publicBase64Key = publicKey.save();
          setPublicBase64Key(publicBase64Key);
          
          // Update UI
          setDivDisabledParms(false);
          setCreatingParms(false);
          setTextColorDisabledParms('rgb(0,0,0)');
          setPowerOff(false);
        }
      })
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

    // Obtain axis arrays
    let arrayX = document.getElementById('valuesXId').value.split(',');
    let arrayY = document.getElementById('valuesYId').value.split(',');
    let N = arrayX.length;

    if (arrayX.length !== N ||
      arrayY.length !== N ||
      N<0) {
        setFillCircleOne('rgba(255, 0, 0, 0.9)');
        setComputingParms(false);
        setServerAnswer(`La longitud de ambos ejes debe ser la misma.`);
        return;
    }

    if (N<4) {
      setFillCircleOne('rgba(255, 0, 0, 0.9)');
      setComputingParms(false);
      setServerAnswer(`Se requiere de la introducción de por lo menos 3 valores para ofrecer un ajuste fiable.`);
      return;
    }

    // Store array values encrypted
    let storeXValues = []; // Array of X axis ciphertexts in base 64
    var plainTextX = seal.PlainText();
    var cipherTextX = seal.CipherText();
    for (let i=0; i<N; i++) {
      const sealArrayX = Float64Array.from([arrayX[i]]);
      encoder.encode(sealArrayX, scale, plainTextX);
      cipherTextX = encryptor.encryptSymmetric(plainTextX);
      storeXValues[i] = cipherTextX.save();
    }
    plainTextX.delete();
    cipherTextX.delete();

    let storeYValues = []; // Array of Y axis ciphertexts in base 64
    var plainTextY = seal.PlainText();
    var cipherTextY = seal.CipherText();
    for (let i=0; i<N; i++) {
      const sealArrayY = Float64Array.from([arrayY[i]]);
      encoder.encode(sealArrayY, scale, plainTextY);
      cipherTextY = encryptor.encryptSymmetric(plainTextY);
      storeYValues[i] = cipherTextY.save();
    }
    plainTextY.delete();
    cipherTextY.delete();

    // POST
    var postData = {
      valuesX: storeXValues,
      valuesY: storeYValues,
      parmsBase64: parmsBase64,
      secLevel: sendSecLevel,
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
      
      // Decrypt
      const decryptedPlainTextNumeratorSlope = decryptor.decrypt(numeratorSlopeEncrypted);
      numeratorSlopeEncrypted.delete();
      const decryptedPlainTextNumeratorCP = decryptor.decrypt(numeratorCutPointEncrypted);
      numeratorCutPointEncrypted.delete();
      const decryptedPlainTextDenominator = decryptor.decrypt(denominatorEncrypted);
      denominatorEncrypted.delete();

      // Decode
      const decodedArrayNumeratorSlope = encoder.decode(decryptedPlainTextNumeratorSlope);
      decryptedPlainTextNumeratorSlope.delete();
      const decodedArrayNumeratorCP = encoder.decode(decryptedPlainTextNumeratorCP);
      decryptedPlainTextNumeratorCP.delete();
      const decodedArrayDenominator = encoder.decode(decryptedPlainTextDenominator);
      decryptedPlainTextDenominator.delete();

      // Compute slope and cut point in y axis
      let m = decodedArrayNumeratorSlope[0] / decodedArrayDenominator[0];
      setM(m);
      let b = decodedArrayNumeratorCP[0] / decodedArrayDenominator[0];
      setB(b);

      // Update UI
      setEncryptedNumSlope(`Numerador pendiente: ${res.data.numeratorSlope.substring(0, 20)}...`);
      setEncryptedNumCP(`Numerador punto de corte eje Y: ${res.data.numeratorCutPoint.substring(0, 20)}...`);
      setEncryptedDen(`Denominador común: ${res.data.denominator.substring(0, 20)}...`);
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

    // Obtain X value for prediction
    let predictX = document.getElementById('valuePredict').value.split(',');

    // Encrypt data to predict y = mx + b
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

    // POST 
     var postData = {
      cipherTextBase64Predict: cipherTextXBase64,
      cipherTextBase64M: cipherTextMBase64,
      cipherTextBase64B: cipherTextBBase64,
      parmsBase64: parmsBase64,
      secLevel: sendSecLevel,
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

      // The format of the JSON to be received is the following: {yPrediction}
      const predictionEncrypted = seal.CipherText();
      predictionEncrypted.load(context, res.data.yPrediction);
      
      // Decrypt
      const decryptedPlainTextPrediction = decryptor.decrypt(predictionEncrypted);
      predictionEncrypted.delete();

      // Decode
      const decodedArrayPrediction = encoder.decode(decryptedPlainTextPrediction);
      decryptedPlainTextPrediction.delete();

      // Compute slope and cut point in y axis
      let y = decodedArrayPrediction[0];

      // Update UI
      setEncryptedPrediction(`y = ${res.data.yPrediction.substring(0, 20)}...`);
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
            {encryptedNumSlope ?
              <div style={{display: 'flex', flexDirection: 'column'}}>
                <h4>Datos cifrados recibidos del servidor:</h4>
                <p>{encryptedNumSlope}</p>
                <p>{encryptedNumCP}</p>
                <p>{encryptedDen}</p>
                <h4>Datos descifrados por el cliente:</h4>
                <p>{serverAnswer}</p>
              </div>
            : <div></div>
            }
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
            {encryptedPrediction ?
              <div style={{display: 'flex', flexDirection: 'column'}}>
                <h4>Datos cifrados recibidos del servidor:</h4>
                <p>{encryptedPrediction}</p>
                <h4>Datos descifrados por el cliente:</h4>
                <p>{serverAnswerTwo}</p>
              </div>
            : <div></div>
            }
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

export default PageOne;