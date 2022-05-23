import React from "react";
import axios from 'axios';
import Swal from 'sweetalert2';
import '../style/pagetwo.css';
import '../style/pageone.css';
import LoadingSpinner from './LoadingSpinner';
import { ReactComponent as PowerOnOff } from '../res/powerOnOff.svg';

const SEAL = require('node-seal');

function PageTwo() {
    // UseState for homomorphic variables
    const [seal, setSeal] = React.useState(null);
    const [parmsBase64, setParmsBase64] = React.useState(null);
    const [parmsStringBase64, setParmsStringBase64] = React.useState(null);
    const [scale, setScale] = React.useState(0);

    const [encoder, setEncoder] = React.useState(null);
    const [encryptor, setEncryptor] = React.useState(null);
    const [decryptor, setDecryptor] = React.useState(null);
    const [encoderString, setEncoderString] = React.useState(null);
    const [encryptorString, setEncryptorString] = React.useState(null);
    const [decryptorString, setDecryptorString] = React.useState(null);

    // UseState for visibility
    const [powerOff, setPowerOff] = React.useState(true);
    const [creatingParms, setCreatingParms] = React.useState(false);
    const [sendingUserToDb, setSendingUserToDb] = React.useState(false);
    const [getUserFromDb, setGetUserFromDb] = React.useState(false);
    const [divDisabledParms, setDivDisabledParms] = React.useState(true);
    const [textColorDisabledParms, setTextColorDisabledParms] = React.useState('rgb(150, 150, 150)');
    const [getAvgWeight, setGetAvgWeight] = React.useState(false);
    const [showDecryptBtn, setShowDecryptBtn] = React.useState(true);
    const [titleDataGet, setTitleDataGet] = React.useState(null);

    // Patient's info received
    const [resData, setResData] = React.useState(null);
    const [decryptUserFromDb, setDecryptUserFromDb] = React.useState(null);
    const [receivedID, setReceivedID] = React.useState(null);
    const [receivedDNI, setReceivedDNI] = React.useState(null);
    const [receivedName, setReceivedName] = React.useState(null);
    const [receivedSurname, setReceivedSurname] = React.useState(null);
    const [receivedTlf, setReceivedTlf] = React.useState(null);
    const [receivedEmail, setReceivedEmail] = React.useState(null);
    const [receivedAge, setReceivedAge] = React.useState(null);
    const [receivedWeight, setReceivedWeight] = React.useState(null);
    const [receivedHeight, setReceivedHeight] = React.useState(null);
    const [encryptedSumWeight, setEncryptedSumWeight] = React.useState(null);
    const [numRegistersBBDD, setNumRegistersBBDD] = React.useState(null);
    const [receivedSumWeight, setReceivedSumWeight] = React.useState(null);


    /**************************************************
     * BYTE ARRAY <-> STRING
     **************************************************/
    function stringToByteArray(s){
        var result = new Uint32Array(s.length);
        for (var i=0; i<s.length; i++){
            result[i] = s.charCodeAt(i);
        }
        return result;
    }

    function byteArrayToString(array) {
        var result = String.fromCharCode(...array);
        return result;
    }

    /**************************************************
     * VALIDATION FUNCTIONS
     **************************************************/
    // DNI
    function validateDNI(value) {
        let number, dni, letter;
        let validRegex = /^[XYZ]?\d{5,8}[A-Z]$/;
        value = value.toUpperCase();
        if (validRegex.test(value) === true) {
            number = value.substr(0, value.length - 1);
            number = number.replace('X', 0);
            number = number.replace('Y', 1);
            number = number.replace('Z', 2);
            dni = value.substr(value.length - 1, 1);
            number = number % 23;
            letter = 'TRWAGMYFPDXBNJZSQVHLCKET';
            letter = letter.substring(number, number + 1);
            if (letter !== dni) {
                return false;
            } else {
                return true;
            }
        } else {
            return false;
        }
    }

    // Email
    function validateEmail(email) {
        var validRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
        if (validRegex.test(email) === true) {
            return true;
        }
        return false;
    }

    /**************************************************
     * CREATE KEYS
     **************************************************/
    async function generateSecretKeys() {
        // Init SEAL
        let seal = await SEAL();

        // Encryption parameters
        // Strings
        const schemeTypeString = seal.SchemeType.bfv;
        const polyModulusDegreeString = 4096;
        const bitSizesString = [36, 36, 37];
        const bitSizeString = 20;
        // Numbers
        const schemeType = seal.SchemeType.ckks;
        const polyModulusDegree = 8192;
        const securityLevel = seal.SecurityLevel.tc128;
        const bitSizes = [59, 43, 43, 59];
        
        // Parms
        const parms = seal.EncryptionParameters(schemeType);
        const parmsString = seal.EncryptionParameters(schemeTypeString);
        
        // PolyModulus Degree
        parms.setPolyModulusDegree(polyModulusDegree);
        parmsString.setPolyModulusDegree(polyModulusDegreeString);
        
        // Coefficient Modulus Primes
        parms.setCoeffModulus(
            seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
        );
        parmsString.setCoeffModulus(
            seal.CoeffModulus.Create(polyModulusDegreeString, Int32Array.from(bitSizesString))
        );

        // PlainModulus for the Strings
        parmsString.setPlainModulus(
            seal.PlainModulus.Batching(polyModulusDegreeString, bitSizeString)
        );
        
        // Create context
        let context = seal.Context(
            parms, // Encryption Parameters
            true, // ExpandModChain
            securityLevel // Enforce a security level
        );
        let contextString = seal.Context(
            parmsString,
            true,
            seal.SecurityLevel.tc128
        )

        // Check correctness and return context
        if (!context.parametersSet() || !contextString.parametersSet()) {
            Swal.fire(
                `Parámetros generados incorrectos`,
                'Contacte con un desarrollador',
                'error'
            ).then(async () => {
                return;
            })
        } else {
            // Numbers
            const keyGenerator = seal.KeyGenerator(context);
            const secretKey = keyGenerator.secretKey();
            const secretBase64Key = secretKey.save();
            // Strings
            const keyGeneratorString = seal.KeyGenerator(contextString);
            const secretKeyString = keyGeneratorString.secretKey();
            const secretBase64KeyString = secretKeyString.save();

            console.log(
                `${secretBase64KeyString}`
            );
            console.log(
                `${secretBase64Key}`
            );
        }
    }


    /**************************************************
     * INITIALIZE SEAL VARIABLES
     **************************************************/
    async function initSEAL() {
        Swal.fire({
            title: '¿Ya tienes tus claves privadas?',
            text: 'Necesitas una clave privada para texto (T) y otra para números (N)',
            icon: 'question',
            showDenyButton: true,
            showCancelButton: true,
            confirmButtonColor: 'rgb(0, 200, 0)',
            confirmButtonText: '¡Ya las tengo!',
            denyButtonText: `¡Aún no!`,
            reverseButtons: true
        }).then((result) => {
            if (result.isConfirmed) {
                generateSEALContext();
            } else if (result.isDenied) {
                generateSecretKeys();
                Swal.fire(
                    'Aquí tienes tus claves privadas', 
                    'Abre la consola para copiarlas (Orden: T, N). Almacénalas en un lugar seguro y no las compartas con nadie.', 
                    'info'
                ).then(async () => {
                    generateSEALContext();
                })
            }
        })
    }

    async function generateSEALContext() {
        Swal.fire({
            title: 'Introduzca la clave secreta T:',
            input: 'text',
            icon: 'question',
            showCancelButton: true,
            confirmButtonColor: 'rgb(0, 200, 0)',
            reverseButtons: true
        }).then(async (secretBase64KeyString) => {
            if (secretBase64KeyString.value) {
                Swal.fire({
                    title: 'Introduzca la clave secreta N:',
                    input: 'text',
                    icon: 'question',
                    showCancelButton: true,
                    confirmButtonColor: 'rgb(0, 200, 0)',
                    reverseButtons: true
                }).then(async (secretBase64Key) => {
                    if (secretBase64Key.value) {
                        // Init SEAL
                        setCreatingParms(true);
                        let seal = await SEAL();
                        setSeal(seal);

                        // Encryption parameters
                        // Strings
                        const schemeTypeString = seal.SchemeType.bfv;
                        const polyModulusDegreeString = 4096;
                        const bitSizesString = [36, 36, 37];
                        const bitSizeString = 20;
                        // Numbers
                        const schemeType = seal.SchemeType.ckks;
                        const polyModulusDegree = 8192;
                        const bitSizes = [59, 43, 43, 59];
                        const bitSize = 43;

                        // Scale
                        let scale = Math.pow(2.0, bitSize);
                        setScale(scale);
                        
                        // Parms
                        const parms = seal.EncryptionParameters(schemeType);
                        const parmsString = seal.EncryptionParameters(schemeTypeString);
                        
                        // PolyModulus Degree
                        parms.setPolyModulusDegree(polyModulusDegree);
                        parmsString.setPolyModulusDegree(polyModulusDegreeString);
                        
                        // Coefficient Modulus Primes
                        parms.setCoeffModulus(
                            seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
                        );
                        parmsString.setCoeffModulus(
                            seal.CoeffModulus.Create(polyModulusDegreeString, Int32Array.from(bitSizesString))
                        );

                        // PlainModulus for the Strings
                        parmsString.setPlainModulus(
                            seal.PlainModulus.Batching(polyModulusDegreeString, bitSizeString)
                        );

                        // Save parms into the stream
                        let parmsBase64 = parms.save();
                        setParmsBase64(parmsBase64);

                        let parmsStringBase64 = parmsString.save();
                        setParmsStringBase64(parmsStringBase64);
                        
                        // Create context
                        let context = seal.Context(
                            parms, // Encryption Parameters
                            true, // ExpandModChain
                            seal.SecurityLevel.tc128 // Enforce a security level
                        );
                        let contextString = seal.Context(
                            parmsString,
                            true,
                            seal.SecurityLevel.tc128
                        )

                        // Check correctness and return context
                        if (!context.parametersSet() || !contextString.parametersSet()) {
                            Swal.fire(
                                `Parámetros generados incorrectos`,
                                'Contacte con un desarrollador.',
                                'error'
                            ).then(async () => {
                                return;
                            })
                        } else {
                            // Homomorphic objects initialization
                            // Numbers
                            let encoder = seal.CKKSEncoder(context);
                            setEncoder(encoder);
                            const secretKey = seal.SecretKey();
                            secretKey.load(context, secretBase64Key.value);
                            const keyGenerator = seal.KeyGenerator(context, secretKey);
                            const publicKey = keyGenerator.createPublicKey();
                            let encryptor = seal.Encryptor(context, publicKey, secretKey);
                            setEncryptor(encryptor);
                            let decryptor = seal.Decryptor(context, secretKey);
                            setDecryptor(decryptor);
            
                            // Strings
                            let encoderString = seal.BatchEncoder(contextString);
                            setEncoderString(encoderString);
                            const secretKeyString = seal.SecretKey();
                            secretKeyString.load(contextString, secretBase64KeyString.value);
                            const keyGeneratorString = seal.KeyGenerator(contextString, secretKeyString);
                            const publicKeyString = keyGeneratorString.createPublicKey();
                            let encryptorString = seal.Encryptor(contextString, publicKeyString, secretKeyString);
                            setEncryptorString(encryptorString);
                            let decryptorString = seal.Decryptor(contextString, secretKeyString);
                            setDecryptorString(decryptorString);
                            
                            // Toggle visibility
                            setDivDisabledParms(false);
                            setCreatingParms(false);
                            setTextColorDisabledParms('rgb(0,0,0)');
                            setPowerOff(false);
                        }

                    }
                })
            }
        })
    }


    /**************************************************
     * SAVE PATIENT INFO IN THE DATABASE
     **************************************************/
    const callServerPost = async () => {
        setSendingUserToDb(true);
        let dni = document.getElementById('dniId').value + '$';
        let name = document.getElementById('nameId').value + '$';
        let surname = document.getElementById('surnameId').value + '$';
        let tlf = document.getElementById('tlfId').value + '$';
        let email = document.getElementById('emailId').value + '$';
        let age = document.getElementById('ageId').value;
        let weight = document.getElementById('weightId').value;
        let height = document.getElementById('heightId').value;

        // Check that all the data has been introduced
        if (dni === "" || name === "" || surname === "" || tlf === "" ||
            email === "" || age === "" || weight === "" || height === "") {
            Swal.fire(
                `Faltan valores por introducir`,
                'Pulse OK para volver a intentarlo.',
                'error'
            ).then(async () => {
                return;
            })
        }

        // Check correctness of data
        // TODO: Comprobar DNI y email y tlf
        if (!validateDNI(document.getElementById('dniId').value)) {
            Swal.fire(
                `Tipo de dato incorrecto`,
                'El formato del DNI no es correcto.',
                'error'
            ).then(async () => {
                return;
            })
        }
        if (!isNaN(name)) {
            Swal.fire(
                `Tipo de dato incorrecto`,
                'El nombre no puede ser un número.',
                'error'
            ).then(async () => {
                return;
            })
        }
        if (!isNaN(surname)) {
            Swal.fire(
                `Tipo de dato incorrecto`,
                'El apellido no puede ser un número.',
                'error'
            ).then(async () => {
                return;
            })
        }
        if (!validateEmail(document.getElementById('emailId').value)) {
            Swal.fire(
                `Tipo de dato incorrecto`,
                'El formato del correo electrónico no es correcto.',
                'error'
            ).then(async () => {
                return;
            })
        }
        if (document.getElementById('tlfId').value.length !== 9) {
            Swal.fire(
                `Tipo de dato incorrecto`,
                'El formato del número de teléfono no es correcto.',
                'error'
            ).then(async () => {
                return;
            })
        }
        if (isNaN(age)) {
            Swal.fire(
                `Tipo de dato incorrecto`,
                'La edad debe ser un número.',
                'error'
            ).then(async () => {
                return;
            })
        }
        if (isNaN(weight)) {
            Swal.fire(
                `Tipo de dato incorrecto`,
                'El peso debe ser un número.',
                'error'
            ).then(async () => {
                return;
            })
        }
        if (isNaN(height)) {
            Swal.fire(
                `Tipo de dato incorrecto`,
                'La altura debe ser un número.',
                'error'
            ).then(async () => {
                return;
            })
        }

        // Encrypt data
        // DNI
        const dniByteArray = stringToByteArray(dni);
        const plainTextDNI = seal.PlainText();
        const sealArrayDNI = Uint32Array.from(dniByteArray);
        encoderString.encode(sealArrayDNI, plainTextDNI);
        const cipherTextDNI = encryptorString.encryptSymmetric(plainTextDNI);
        const cipherTextDNIBase64 = cipherTextDNI.save();
        plainTextDNI.delete();
        cipherTextDNI.delete();

        // Name
        const nameByteArray = stringToByteArray(name);
        const plainTextName = seal.PlainText();
        const sealArrayName = Uint32Array.from(nameByteArray);
        encoderString.encode(sealArrayName, plainTextName);
        const cipherTextName = encryptorString.encryptSymmetric(plainTextName);
        const cipherTextNameBase64 = cipherTextName.save();
        plainTextName.delete();
        cipherTextName.delete();

        // Surname
        const surnameByteArray = stringToByteArray(surname);
        const plainTextSurname = seal.PlainText();
        const sealArraySurname = Uint32Array.from(surnameByteArray);
        encoderString.encode(sealArraySurname, plainTextSurname);
        const cipherTextSurname = encryptorString.encryptSymmetric(plainTextSurname);
        const cipherTextSurnameBase64 = cipherTextSurname.save();
        plainTextSurname.delete();
        cipherTextSurname.delete();

        // Tlf
        const tlfByteArray = stringToByteArray(tlf);
        const plainTextTlf = seal.PlainText();
        const sealArrayTlf = Uint32Array.from(tlfByteArray);
        encoderString.encode(sealArrayTlf, plainTextTlf);
        const cipherTextTlf = encryptorString.encryptSymmetric(plainTextTlf);
        const cipherTextTlfBase64 = cipherTextTlf.save();
        plainTextTlf.delete();
        cipherTextTlf.delete();

        // Email
        const emailByteArray = stringToByteArray(email);
        const plainTextEmail = seal.PlainText();
        const sealArrayEmail = Uint32Array.from(emailByteArray);
        encoderString.encode(sealArrayEmail, plainTextEmail);
        const cipherTextEmail = encryptorString.encryptSymmetric(plainTextEmail);
        const cipherTextEmailBase64 = cipherTextEmail.save();
        plainTextEmail.delete();
        cipherTextEmail.delete();

        // Age
        const plainTextAge = seal.PlainText();
        const sealArrayAge = Float64Array.from([age]);
        encoder.encode(sealArrayAge, scale, plainTextAge);
        const cipherTextAge = encryptor.encryptSymmetric(plainTextAge);
        const cipherTextAgeBase64 = cipherTextAge.save();
        plainTextAge.delete();
        cipherTextAge.delete();
        

        // Weight
        const plainTextW = seal.PlainText();
        const sealArrayW = Float64Array.from([weight]);
        encoder.encode(sealArrayW, scale, plainTextW);
        const cipherTextW = encryptor.encryptSymmetric(plainTextW);
        const cipherTextWBase64 = cipherTextW.save();
        plainTextW.delete();
        cipherTextW.delete();

        // Height
        const plainTextH = seal.PlainText();
        const sealArrayH = Float64Array.from([height]);
        encoder.encode(sealArrayH, scale, plainTextH);
        const cipherTextH = encryptor.encryptSymmetric(plainTextH);
        const cipherTextHBase64 = cipherTextH.save();
        plainTextH.delete();
        cipherTextH.delete();

        // Post data
        var postData = {
            parms: parmsBase64,
            parmsString: parmsStringBase64,
            dni: cipherTextDNIBase64,
            name: cipherTextNameBase64,
            surname: cipherTextSurnameBase64,
            tlf: cipherTextTlfBase64,
            email: cipherTextEmailBase64,
            age: cipherTextAgeBase64,
            weight: cipherTextWBase64,
            height: cipherTextHBase64
        };
        
        let axiosConfig = {
            headers: {
                'Content-Type': 'application/json;charset=UTF-8',
                "Access-Control-Allow-Origin": "*",
            }
        };

        await axios.post('http://localhost:3000/api/patients', postData, axiosConfig)
        .then(res => {
            setReceivedID(`Identificador recibido: ${res.data}`);
            setSendingUserToDb(false);
        }).catch(err => {
            console.log(err.message);
            setSendingUserToDb(false);
            Swal.fire(
                `El DNI ya está registrado en la base de datos`,
                'Pulse OK para introducir otro paciente.',
                'error'
            ).then(async () => {
                document.getElementById('dniId').value = "";
                document.getElementById('nameId').value = "";
                document.getElementById('surnameId').value = "";
                document.getElementById('tlfId').value = "";
                document.getElementById('emailId').value = "";
                document.getElementById('ageId').value = "";
                document.getElementById('weightId').value = "";
                document.getElementById('heightId').value = "";
                return;
            })
        });
    }

    /**************************************************
     * GET A PATIENT'S INFO GIVEN HIS/HER ID
     **************************************************/
    const callServerGet = async () => {
        setGetUserFromDb(true);
        let id = document.getElementById('idPatientId').value;

        let axiosConfig = {
            headers: {
                'Content-Type': 'application/json;charset=UTF-8',
                "Access-Control-Allow-Origin": "*",
            }
        };

        await axios.get(`http://localhost:3000/api/patients?id=${id}`, axiosConfig)
        .then(res => {
            setShowDecryptBtn(true);
            setGetUserFromDb(false);
            setResData(res.data);
            setTitleDataGet('Datos cifrados recibidos del servidor:');
            
            // Show encrypted data
            setReceivedDNI(`DNI: ${res.data.dni.substring(0, 20)}...`);
            setReceivedName(`Nombre: ${res.data.name.substring(0, 20)}...`);
            setReceivedSurname(`Apellidos: ${res.data.surname.substring(0, 20)}...`);
            setReceivedTlf(`Teléfono: ${res.data.tlf.substring(0, 20)}...`);
            setReceivedEmail(`Correo electrónico: ${res.data.email.substring(0, 20)}...`);
            setReceivedAge(`Edad: ${res.data.age.substring(0, 20)}...`);
            setReceivedWeight(`Peso: ${res.data.weight.substring(0, 20)}...`);
            setReceivedHeight(`Altura: ${res.data.height.substring(0, 20)}...`);

        }).catch(err => {
            console.log(err.message);
            setGetUserFromDb(false);
            Swal.fire(
                `Identificador incorrecto`,
                'Pulse OK para introducir otro paciente.',
                'error'
            ).then(async () => {
                document.getElementById('idPatientId').value = "";
                return;
            })
        });
    }

    /**************************************************
     * DECRYPT PATIENT'S INFO
     **************************************************/
    function decryptPatient () {
        setShowDecryptBtn(false);
        setDecryptUserFromDb(true);
        setTitleDataGet('Datos descifrados por el cliente:');
        // Generate context from the one used to encrypt the data
        // Numbers
        const parms = seal.EncryptionParameters();
        parms.load(resData.parms);
        const contextRcv = seal.Context(
            parms, // Encryption Parameters
            true, // ExpandModChain
            seal.SecurityLevel.tc128 // Enforce a security level
        );
        const encoderRcv = seal.CKKSEncoder(contextRcv);
        
        // Strings
        const parmsString = seal.EncryptionParameters();
        parmsString.load(resData.parmsString);
        const contextStringRcv = seal.Context(
            parmsString,
            true,
            seal.SecurityLevel.tc128
        );
        const encoderStringRcv = seal.BatchEncoder(contextStringRcv);


        // Desencriptar la info del paciente
        // DNI
        const DNIEncrypted = seal.CipherText();
        DNIEncrypted.load(contextStringRcv, resData.dni);
        const decryptedPlainTextDNI = decryptorString.decrypt(DNIEncrypted);
        DNIEncrypted.delete();
        const decodedDNI = encoderStringRcv.decode(decryptedPlainTextDNI);
        decryptedPlainTextDNI.delete();
        let decodedDNIString = byteArrayToString(decodedDNI);
        setReceivedDNI(`DNI: ${decodedDNIString.substring(0, decodedDNIString.indexOf('$'))}`);

        // Name
        const NameEncrypted = seal.CipherText();
        NameEncrypted.load(contextStringRcv, resData.name);
        const decryptedPlainTextName = decryptorString.decrypt(NameEncrypted);
        NameEncrypted.delete();
        const decodedName = encoderStringRcv.decode(decryptedPlainTextName);
        decryptedPlainTextName.delete();
        let decodedNameString = byteArrayToString(decodedName);
        setReceivedName(`Nombre: ${decodedNameString.substring(0, decodedNameString.indexOf('$'))}`);

        // Surname
        const SurnameEncrypted = seal.CipherText();
        SurnameEncrypted.load(contextStringRcv, resData.surname);
        const decryptedPlainTextSurname = decryptorString.decrypt(SurnameEncrypted);
        SurnameEncrypted.delete();
        const decodedSurname = encoderStringRcv.decode(decryptedPlainTextSurname);
        decryptedPlainTextSurname.delete();
        let decodedSurnameString = byteArrayToString(decodedSurname);
        setReceivedSurname(`Apellidos: ${decodedSurnameString.substring(0, decodedSurnameString.indexOf('$'))}`);

        // Tlf
        const TlfEncrypted = seal.CipherText();
        TlfEncrypted.load(contextStringRcv, resData.tlf);
        const decryptedPlainTextTlf = decryptorString.decrypt(TlfEncrypted);
        TlfEncrypted.delete();
        const decodedTlf = encoderStringRcv.decode(decryptedPlainTextTlf);
        decryptedPlainTextTlf.delete();
        let decodedTlfString = byteArrayToString(decodedTlf);
        setReceivedTlf(`Teléfono: ${decodedTlfString.substring(0, decodedTlfString.indexOf('$'))}`);

        // Email
        const EmailEncrypted = seal.CipherText();
        EmailEncrypted.load(contextStringRcv, resData.email);
        const decryptedPlainTextEmail = decryptorString.decrypt(EmailEncrypted);
        EmailEncrypted.delete();
        const decodedEmail = encoderStringRcv.decode(decryptedPlainTextEmail);
        decryptedPlainTextEmail.delete();
        let decodedEmailString = byteArrayToString(decodedEmail);
        setReceivedEmail(`Correo electrónico: ${decodedEmailString.substring(0, decodedEmailString.indexOf('$'))}`);

        // Age
        const AgeEncrypted = seal.CipherText();
        AgeEncrypted.load(contextRcv, resData.age);
        const decryptedPlainTextAge = decryptor.decrypt(AgeEncrypted);
        AgeEncrypted.delete();
        const decodedAge = encoderRcv.decode(decryptedPlainTextAge);
        decryptedPlainTextAge.delete();
        setReceivedAge(`Edad: ${Math.round(decodedAge[0])}`);

        // Weight
        const WeightEncrypted = seal.CipherText();
        WeightEncrypted.load(contextRcv, resData.weight);
        const decryptedPlainTextWeight = decryptor.decrypt(WeightEncrypted);
        WeightEncrypted.delete();
        const decodedWeight = encoderRcv.decode(decryptedPlainTextWeight);
        decryptedPlainTextWeight.delete();
        setReceivedWeight(`Peso: ${decodedWeight[0].toFixed(1)}`);

        // Height
        const HeightEncrypted = seal.CipherText();
        HeightEncrypted.load(contextRcv, resData.height);
        const decryptedPlainTextHeight = decryptor.decrypt(HeightEncrypted);
        HeightEncrypted.delete();
        const decodedHeight = encoderRcv.decode(decryptedPlainTextHeight);
        decryptedPlainTextHeight.delete();
        setReceivedHeight(`Altura: ${decodedHeight[0].toFixed(1)}`);
        setDecryptUserFromDb(false);
    }

    /**************************************************
     * GET AVERAGE WEIGHT OF ALL PATIENTS
     **************************************************/
     const callServerGetAvgWeight = async () => {
        setGetAvgWeight(true);

        let axiosConfig = {
            headers: {
                'Content-Type': 'application/json;charset=UTF-8',
                "Access-Control-Allow-Origin": "*",
            }
        };

        await axios.get(`http://localhost:3000/api/avgweight`, axiosConfig)
        .then(res => {
            setGetAvgWeight(false);
            // Generate context from the one used to encrypt the data
            // Numbers
            const parms = seal.EncryptionParameters();
            parms.load(res.data.parms);
            const contextRcv = seal.Context(
                parms, // Encryption Parameters
                true, // ExpandModChain
                seal.SecurityLevel.tc128 // Enforce a security level
            );
            const encoderRcv = seal.CKKSEncoder(contextRcv);

            // Receive data
            const sumEncrypted = seal.CipherText();
            sumEncrypted.load(contextRcv, res.data.encryptedSum);
            const decryptedPlainTextSum = decryptor.decrypt(sumEncrypted);
            sumEncrypted.delete();
            const decodedSum = encoderRcv.decode(decryptedPlainTextSum);
            decryptedPlainTextSum.delete();

            // Update UI
            setEncryptedSumWeight(`Suma de los pesos cifrada: ${res.data.encryptedSum.substring(0, 20)}...`)
            setNumRegistersBBDD(`Número de registros almacenados: ${res.data.numElements}`);
            setReceivedSumWeight(`Media de los pesos: ${decodedSum[0]/(res.data.numElements)}`);

        }).catch(err => {
            console.log(err.message);
            setGetAvgWeight(false);
            Swal.fire(
                `No se puede realizar esta acción`,
                '¿Hay usuarios registrados? Pulse OK para continuar.',
                'error'
            ).then(async () => {
                return;
            })
        });
    }




    /**************************************************
     * SHOW UI
     **************************************************/
    return (
        <div style={{display: 'flex', flexDirection: 'row'}}>
            <button onClick={initSEAL} className="btnInitSEAL">
                {creatingParms ? <LoadingSpinner/> : 
                (powerOff ? <PowerOnOff className='icon__off' fill='rgba(255, 0, 0, 0.9)'/> : 
                <PowerOnOff className='icon__on' fill='rgba(0, 255, 0, 0.9)'/>)}
            </button>
            <div className="userForm" style={{width: '20rem'}}>
                <form style={{display: 'flex', flexDirection: 'column', alignItems: 'center', width: '100%'}}>
                    <h4 style={{color: textColorDisabledParms}}>Introducir datos del paciente</h4>
                    <input type="text" className="inputFirstForm" name="dni" id="dniId" 
                    placeholder='DNI' disabled={divDisabledParms}/>
                    <input type="text" className="inputFirstForm" name="name" id="nameId" 
                    placeholder='Nombre' disabled={divDisabledParms}/>
                    <input type="text" className="inputFirstForm" name="surname" id="surnameId" 
                    placeholder='Apellidos' disabled={divDisabledParms}/>

                    <input type="text" className="inputFirstForm" name="tlf" id="tlfId" 
                    placeholder='Teléfono' disabled={divDisabledParms}/>
                    <input type="text" className="inputFirstForm" name="surname" id="emailId" 
                    placeholder='Correo electrónico' disabled={divDisabledParms}/>
                    <input type="text" className="inputFirstForm" name="age" id="ageId" 
                    placeholder='Edad' disabled={divDisabledParms}/>

                    <input type="text" className="inputFirstForm" name="weight" id="weightId" 
                    placeholder='Peso' disabled={divDisabledParms}/>
                    <input type="text" className="inputFirstForm" name="height" id="heightId" 
                    placeholder='Altura' disabled={divDisabledParms}/>
                </form>
                <button onClick={callServerPost} className="btnFirstForm" disabled={divDisabledParms}>
                    {sendingUserToDb ? <LoadingSpinner/> : 'Guardar'}
                </button>
                {receivedID ? 
                    <div style={{textAlign: 'center', display: 'flex'}}>
                        <p>{receivedID}</p>
                    </div>
                : <div></div>
                }
            </div>
            <div style={{display: 'flex', flexDirection: 'column', width: '25rem'}}>
                <div className="userForm" style={{marginBottom: '5%', width: '25rem'}}>
                    <form style={{display: 'flex', flexDirection: 'column', alignItems: 'center', width: '20rem'}}>
                        <h4 style={{color: textColorDisabledParms}}>Obtener información del paciente</h4>
                        <input type="text" className="inputFirstForm" name="id" id="idPatientId" 
                        placeholder='Identificador' disabled={divDisabledParms}/>
                    </form>
                    <button onClick={callServerGet} className="btnFirstForm" disabled={divDisabledParms}>
                        {getUserFromDb ? <LoadingSpinner/> : 'Solicitar'}
                    </button>
                    {receivedDNI ? 
                        <div style={{display: 'flex', flexDirection: 'column'}}>
                            <h4>{titleDataGet}</h4>
                            <p>{receivedDNI}</p>
                            <p>{receivedName}</p>
                            <p>{receivedSurname}</p>
                            <p>{receivedTlf}</p>
                            <p>{receivedEmail}</p>
                            <p>{receivedAge}</p>
                            <p>{receivedWeight}</p>
                            <p>{receivedHeight}</p>
                            {showDecryptBtn ?
                                <button onClick={decryptPatient} className="btnFirstForm">
                                    {decryptUserFromDb ? <LoadingSpinner/> : 'Descifrar'}
                                </button>
                            : <div></div>
                            }
                        </div>
                    : <div></div>
                    }
                </div>
                <div className="userForm" style={{width: '25rem'}}>
                    <h4 style={{color: textColorDisabledParms}}>Obtener la media de los pesos de todos los pacientes registrados</h4>
                    <button onClick={callServerGetAvgWeight} className="btnFirstForm" disabled={divDisabledParms}>
                        {getAvgWeight ? <LoadingSpinner/> : 'Solicitar'}
                    </button>
                    {encryptedSumWeight ? 
                        <div style={{textAlign: 'center', display: 'flex', flexDirection: 'column'}}>
                            <h4>Datos cifrados recibidos del servidor:</h4>
                            <p>{encryptedSumWeight}</p>
                            <p>{numRegistersBBDD}</p>
                            <h4>Datos descifrados por el cliente:</h4>
                            <p>{receivedSumWeight}</p>
                        </div>
                    : <div></div>
                    }
                </div>
            </div>
        </div>
    )

}

export default PageTwo;