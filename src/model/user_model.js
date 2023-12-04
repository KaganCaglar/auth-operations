const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    ad: {
        type: String,
        required: [true,"Ad alanı boş olamaz"],
        trim: true,
        minlength: 2,
        maxlength:30
    },
    soyad: {
        type: String,
        required: true,
        trim: true,
        minlength: 2,
        maxlength:[30,"soyadı maksimum 30 karakter olmalı"]
    },
    email: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true
        
    },
    avatar: {
        type: String,
        default:'default.png' 
    },
    emailAktif: {
        type: Boolean,
        default: false
    },
    sifre: {
        type: String,
        required: true,
        trim: true,
    }
}, { collection: 'kullanicilar', timestamps: true });

const User = mongoose.model('User', UserSchema);

module.exports = User;