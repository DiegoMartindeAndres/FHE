import './App.css';
import axios from 'axios';
import React from "react";
const SEAL = require('node-seal');

function App() {
  const [serverAnswer, setServerAnswer] = React.useState(null);

  const callServer = async () => {

    /**************************************************
     * OBTAIN AXIS ARRAYS
     **************************************************/
    let arrayX = document.getElementById('valuesXId').value.split(',');
    let arrayY = document.getElementById('valuesYId').value.split(',');
    let N = arrayX.length;
    let title = document.getElementById('titleId').value;

    if (arrayX.length != N ||
      arrayY.length != N ||
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
     * INIT SEAL
     **************************************************/
    const seal = await SEAL();

    /**************************************************
     * SCHEME PARAMETERS
     **************************************************/
    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 8192;
    const bitSizes = [50, 30, 30, 30, 50];
    const bitSize = 30;
    const scale = Math.pow(2.0, bitSize);
    
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
    const context = seal.Context(
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
    }
    
    /**************************************************
     * HOMOMORPHIC OBJECTS INITIALIZATION
     **************************************************/
     const encoder = seal.CKKSEncoder(context);
     const keyGenerator = seal.KeyGenerator(context);
     const publicKey = keyGenerator.createPublicKey();
     const secretKey = keyGenerator.secretKey();
     const relinKey = keyGenerator.createRelinKeys();
     const encryptor = seal.Encryptor(context, publicKey, secretKey);
     const decryptor = seal.Decryptor(context, secretKey);

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

    // Send relin key as Base64
    const relinBase64Key = relinKey.save();
    const publicBase64Key = publicKey.save();

    var postData = {
      valuesX: storeXValues,
      valuesY: storeYValues,
      relinBase64Key: relinBase64Key,
      publicBase64Key: publicBase64Key,
      title: title
    };
    
    let axiosConfig = {
      headers: {
          'Content-Type': 'application/json;charset=UTF-8',
          "Access-Control-Allow-Origin": "*",
      }
    };

    await axios.post('http://localhost:3000/api/operate', postData, axiosConfig)
    .then(res => {
      console.log('received');
      /* const uploadedCipherText = seal.CipherText();
      uploadedCipherText.load(context, res.data);

      // Decrypt the CipherText
      const decryptedPlainText = decryptor.decrypt(uploadedCipherText);
      
      // Decode the PlainText
      const decodedArray = encoder.decode(decryptedPlainText);
      
      setServerAnswer(decodedArray[0]); */
    }).catch(err => console.log(err.response.data));
  }

  return (
    <div className="App" style={{display: 'flex', flexDirection: 'column', alignItems: 'center'}}>
      <form style={{display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '2%'}}>
        <label style={{paddingBottom: '2%'}}>
          X axis:
          <input type="text" name="X axis" id="valuesXId"/>
        </label>
        <label style={{paddingBottom: '2%'}}>
          Y axis:
          <input type="text" name="Y axis" id="valuesYId"/>
        </label>
        <label style={{paddingBottom: '2%'}}>
          Title:
          <input type="text" name="Title" id="titleId"/>
        </label>
      </form>
      <button onClick={callServer} style={{width: '50%', marginBottom: '2%', padding: '1%'}}>
          Axios
      </button>
      <h4>
        {
          serverAnswer
        }
      </h4>
    </div>
  );
}

export default App;
