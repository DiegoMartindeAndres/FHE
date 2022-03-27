# Lista de URLs para la API de Microsoft SEAL

## Compute parameters for linear regression

### GET URL

> http://localhost:3000/api/parms-linear/

### POST URLs

#### Altura vs Peso

> http://localhost:3000/api/parms-linear/?valuesX=150,156,160,164,170,173,180,183,190,193&valuesY=44,50,55,60,66.5,70,76.4,79,88,90&title=AlturaVsPeso


## Compute prediction for linear regression

### GET URL

> http://localhost:3000/api/compute-linear/?title=AlturaVsPeso&predict=175


##### Bibliografía

> https://riucv.ucv.es/bitstream/handle/20.500.12466/1925/UTILIDAD%20DE%20LA%20REGRESI%C3%93N%20LINEAL%20M%C3%9ALTIPLE%20EN%20ESTUDIOS%20DE%20CIENCIAS%20DE%20LA%20SALUD.pdf?sequence=1&isAllowed=y
