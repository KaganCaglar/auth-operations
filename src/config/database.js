const mongoose = require('mongoose');
const dotenv = require('dotenv');
const winston = require('./utils/logger'); // Logger'ı buradan alın

// .env dosyasını yükle
dotenv.config();

// MongoDB bağlantı dizesini çevresel değişkenden al
const uri = process.env.MONGODB_URI;

// MongoDB bağlantısını gerçekleştir
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false });

const connection = mongoose.connection;

connection.once('open', () => {
    winston.info('Successfully connected to MongoDB database');
});

connection.on('error', (err) => {
    winston.error('MongoDB connection error:', err);
});