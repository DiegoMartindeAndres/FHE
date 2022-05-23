const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        // MongoDB connection
        const uri = 'mongodb+srv://admin:admin1@cluster0.6vrjq.mongodb.net/users?retryWrites=true&w=majority'
        const con = await mongoose.connect(uri, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log(`MongoDB connected: ${con.connection.host}`);
    } catch (err) {
        console.error(err);
    }
}

module.exports = connectDB;