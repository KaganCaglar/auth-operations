
const mongoose = require('mongoose');

const uri = 'mongodb+srv://cglr24:cglr24@cluster0.doa5dkf.mongodb.net/';

mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });

const connection = mongoose.connection;
connection.once('open', () => {
    console.log('MongoDB veritabanına başarıyla bağlandı');
});