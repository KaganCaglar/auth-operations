const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    ad: {
        type: String,
        required: [true, "Ad alanı boş olamaz"],
        trim: true,
        minlength: 2,
        maxlength: 30
    },
    soyad: {
        type: String,
        required: [true, "Soyad alanı boş olamaz"],
        trim: true,
        minlength: 2,
        maxlength: [30, "Soyadı maksimum 30 karakter olmalı"]
    },
    email: {
        type: String,
        required: [true, "E-posta alanı boş olamaz"],
        trim: true,
        unique: true,
        lowercase: true
    },
    avatar: {
        type: String,
        default: 'default.png'
    },
    emailActive: {
        type: Boolean,
        default: false
    },
    sifre: {
        type: String,
        required: [true, "Şifre alanı boş olamaz"],
        trim: true
    }
}, { collection: 'kullanicilar', timestamps: true });

// Mongoose modelini oluştur
const User = mongoose.model('User', UserSchema);

// Modeli dışa aktar
module.exports = User;
