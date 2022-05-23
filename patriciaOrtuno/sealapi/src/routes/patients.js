const {Router} = require('express');
const router = Router();
var Userdb = require('../model/model');

router.post('/', (req, res) => {
    // Create new user
    const user = new Userdb ({
        parms: req.body.parms,
        parmsString: req.body.parmsString,
        dni: req.body.dni,
        name: req.body.name,
        surname: req.body.surname,
        tlf: req.body.tlf,
        email: req.body.email,
        age: req.body.age,
        weight: req.body.weight,
        height: req.body.height
    });

    // Save new user into the database
    user
    .save(user)
    .then(data => {
        res.send(data._id);
    }).catch(err => {
        console.log(err);
        res.status(500).send({
            message: err.message || "Ha ocurrido un error durante la operación"
        });
    });
});

router.get('/', (req, res) => {
    if (req.query.id) {
        const id = req.query.id;

        Userdb.findById(id)
            .then(data =>{
                if (!data) {
                    res.status(404).send({ message : "No se ha encontrado el usuario de identificador: " + id})
                } else {
                    res.send(data)
                }
            })
            .catch(err => {
                res.status(500).send({ message: "No se ha podido obtener el usuario de identificador: " + id})
            })
    }
})

module.exports = router;