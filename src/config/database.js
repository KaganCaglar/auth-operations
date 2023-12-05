const mongoose = require('mongoose');
const dotenv = require('dotenv');

// .env dosyasını yükle
dotenv.config();

// MongoDB bağlantı dizesini çevresel değişkenden al
const uri = process.env.MONGODB_URI;

// MongoDB bağlantısını gerçekleştir
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false });

const connection = mongoose.connection;

// Bağlantı açıldığında bir kere çalışacak olan fonksiyon
connection.once('open', () => {
    console.log('MongoDB veritabanına başarıyla bağlandı');
});

// Hata durumunda konsola yazdır
connection.on('error', (err) => {
    console.error('MongoDB bağlantı hatası:', err);
});