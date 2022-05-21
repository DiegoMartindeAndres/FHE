# Change Log

Todos los cambios relevantes de este proyecto serán reflejados en este documento.

## v1.0
### 04/04/2022

[+] README.md.
[+] Índice de rutas y definición de características de la API -> index.js.
[+] Interfaz CRUD con JSON de prueba para el cómputo de parámetros de la regresión lineal con encriptado y desencriptado en un mismo punto -> parmsLinear.js.
[+] Método POST de prueba para el cómputo de la predicción con encriptado y desencriptado en un mismo punto -> computeLinear.js.

[+] Método POST para el servidor de la arquitectura de 2 capas que calcula los parámetros de la regresión lineal a raíz de unos valores encriptados recibidos del cliente -> parmsLinearReg.js.
[+] Método POST para el servidor de la arquitectura de 2 capas que calcula la predicción en el eje Y dados unos parámetros de regresión lineal y un valor en X encriptados recibidos del cliente -> predictLinearReg.js.

## v2.0.0
### 05/05/2022

[+] Modificado el índice para incluir las nuevas rutas relacionadas con el sistema de persistencia.
[+] Conexión con la base de datos de MongoDB Atlas alojada en AWS -> database/connection.js
[+] Definido el modelo de datos para un paciente -> model/model.js

[-] Interfaz CRUD con JSON de prueba para el cómputo de parámetros de la regresión lineal con encriptado y desencriptado en un mismo punto -> routes/parmsLinear.js.
[-] Método POST de prueba para el cómputo de la predicción con encriptado y desencriptado en un mismo punto -> routes/computeLinear.js.

[+] Método POST para recibir datos cifrados de un paciente y almacenarlos en la base de datos -> routes/patients.js
[+] Método GET para obtener los datos cifrados de un paciente almacenados en la base de datos -> routes/patients.js
[+] Método GET para obtener la media cifrada del peso de todos los pacientes registrados en la base de datos ->
routes/avgweight.js