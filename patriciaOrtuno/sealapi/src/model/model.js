const mongoose = require('mongoose');

var schema = new mongoose.Schema({
    parms: {
        type: String,
        required: true
    },
    parmsString: {
        type: String,
        required: true
    },
    dni: {
        type: String,
        required: true,
        unique: true
    },
    name: {
        type: String,
        required: true
    },
    surname: {
        type: String,
        required: true
    },
    tlf: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    age: {
        type: String,
        required: true
    },
    weight: {
        type: String,
        required: true
    },
    height: {
        type: String,
        required: true
    }
})

module.exports = mongoose.model('userdb', schema);