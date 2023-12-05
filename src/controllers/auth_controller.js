const { validationResult } = require('express-validator');
const User = require('../model/user_model');
const passport = require('passport');
require('../config/passport_local')(passport);
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const constants = require('./constants');
const util = require('util');

const renderPage = (res, page, title) => {
    res.render(page, { layout: './layout/auth_layout.ejs', title });
};

const showLoginForm = (req, res, next) => {
    renderPage(res, 'login', constants.LOGIN_PAGE_TITLE);
};

// Flash mesajlarını ayarlamak için yardımcı fonksiyon
const setFlashMessages = (req, hatalar) => {
    req.flash('email', req.body.email);
    req.flash('sifre', req.body.sifre);
    req.flash('validation_error', hatalar.array());
};

const handleAuthentication = (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/yonetim',
        failureRedirect: '/login',
        failureFlash: true
    })(req, res, next);
};

const login = (req, res, next) => {
    const hatalar = validationResult(req);

    if (!hatalar.isEmpty()) {
        setFlashMessages(req, hatalar);
        res.redirect('/login');
    } else {
        handleAuthentication(req, res, next);
    }
};
const showRegisterForm = (req, res, next) => {
    renderPage(res, 'register', constants.REGISTER_PAGE_TITLE);
};

// Onay e-postası için JWT üretme fonksiyonu
const generateJWT = (user) => {
    const jwtBilgileri = {
        id: user.id,
        mail: user.email
    };
    return jwt.sign(jwtBilgileri, process.env.CONFIRM_MAIL_JWT_SECRET, { expiresIn: '1d' });
};

const sendEmail = async (email, jwtToken) => {
    const url = process.env.WEB_SITE_URL + 'verify?id=' + jwtToken;
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_SIFRE
        }
    });

    await transporter.sendMail({
        from: 'Nodejs Uygulaması <info@nodejskursu.com>',
        to: email,
        subject: 'Emailiniz Lütfen Onaylayın',
        text: 'Emailinizi onaylamak için lütfen şu linki tıklayın:' + url
    });
};

const handleRegistrationErrors = (req, res, hatalar) => {
    req.flash('validation_error', hatalar.array());
    req.flash('email', req.body.email);
    req.flash('ad', req.body.ad);
    req.flash('soyad', req.body.soyad);
    req.flash('sifre', req.body.sifre);
    req.flash('resifre', req.body.resifre);
    res.redirect('/register');
};

const handleExistingUserError = (req, res) => {
    const validationError = [{msg : constants.VALIDATION_ERROR}];
    req.flash('validation_error', validationError);
    req.flash('email', req.body.email);
    req.flash('ad', req.body.ad);
    req.flash('soyad', req.body.soyad);
    req.flash('sifre', req.body.sifre);
    req.flash('resifre', req.body.resifre);
    res.redirect('/register');
};

const createAndSaveNewUser = async (formData) => {
    const { email: userEmail, ad, soyad, sifre: rawSifre } = formData;
    const hashedSifre = await bcrypt.hash(rawSifre, 10);

    const newUser = new User({
        email: userEmail,
        ad,
        soyad,
        sifre: hashedSifre
    });

    return await newUser.save();
};

const sendVerification = async (newUser, req, res) => {
    const { id, email } = newUser;
    const jwtBilgileri = {
        id,
        mail: email
    };

    const jwtToken = generateJWT(newUser);

    const url = process.env.WEB_SITE_URL + 'verify?id=' + jwtToken;
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_SIFRE
    }
});

try {
    await transporter.sendMail({
        from: 'Nodejs Uygulaması <info@nodejskursu.com>',
        to: newUser.email,
        subject: 'Emailiniz Lütfen Onaylayın',
        text: 'Emailinizi onaylamak için lütfen şu linki tıklayın: ' + url
    });

    console.log('Email başarıyla gönderildi.');
    return true;
} catch (error) {
    console.error('Email gönderirken bir hata oluştu:', error);
    return false;
   
}
};
const showForgotPasswordForm = (req, res, next) => {
    renderPage(res, 'forget_password', constants.FORGET_PASSWORD_PAGE_TITLE);
};

const forgetPassword = async (req, res, next) => {
    const hatalar = validationResult(req);

    if (!hatalar.isEmpty()) { 
        req.flash('validation_error', hatalar.array());
        req.flash('email', req.body.email);
        res.redirect('/forget-password');
    } else {
        try {
            await handleForgetPassword(req, res);
        } catch (err) {
            console.log('user kaydedilirken hata çıktı ' + err);
        }
    }
};

const handleForgetPassword = async (req, res) => {
    const _user = await User.findOne({ email: req.body.email, emailAktif:true });

    if (_user) {
        const jwtBilgileri = {
            id: _user._id,
            mail: _user.email
        };
        const secret = process.env.RESET_PASSWORD_JWT_SECRET + "-" + _user.sifre;
        const jwtToken = jwt.sign(jwtBilgileri, secret, { expiresIn: '1d' });

        const url = process.env.WEB_SITE_URL + 'reset-password/' + _user._id + "/" + jwtToken;
                
        let transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_SIFRE
            }
        });

        const createTransporter = () => {
            return nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.GMAIL_USER,
                    pass: process.env.GMAIL_SIFRE
                }
            });
        };
        
        const sendEmail = async (transporter, email, url) => {
            try {
                await transporter.sendMail({
                    from: 'Nodejs Uygulaması <info@nodejskursu.com>',
                    to: email,
                    subject: 'Şifre Güncelleme',
                    text: 'Şifrenizi oluşturmak için lütfen şu linki tıklayın:' + url
                });
        
                console.log("E-posta başarıyla gönderildi.");
            } catch (error) {
                console.error("E-posta gönderme hatası:", error);
                throw error;
            }
        };
        
        const sendResetPasswordEmail = async (email, url) => {
            const transporter = createTransporter();
            await sendEmail(transporter, email, url);
        };

        req.flash('success_message', [{ msg: constants.SUCCESS_MAIL_CHECK }]);
        res.redirect('/login');
    } else {
        req.flash('validation_error', [{msg : constants.INVALID_EMAIL_OR_INACTIVE_USER}]);
        req.flash('email', req.body.email);
        res.redirect('forget-password');
    }
};
const register = async (req, res, next) => {
    const hatalar = validationResult(req);
    
    if (!hatalar.isEmpty()) { 
        handleRegistrationErrors(req, res, hatalar);
    } else {
        try {
            const existingUser = await User.findOne({ email: req.body.email });
            
            if (existingUser && existingUser.emailAktif) {
                handleExistingUserError(req, res);
            } else {
                if (existingUser) { 
                    await User.findByIdAndRemove({ _id: existingUser._id });
                }
                
                const newUser = await createAndSaveNewUser(req.body);
    
                await sendVerification(newUser, req, res);
    
                req.flash('success_message', [{ msg: 'Başarıyla kayıt oldunuz. Lütfen e-postanızı kontrol edin ve hesabınızı doğrulayın.' }]);
                res.redirect('/login');
            }
        } catch (err) {
            console.log('user kaydedilirken hata çıktı ' + err);
        }
    }
};

const logout = (req, res, next) => {
    req.logout();
    req.session.destroy((error) => {
        res.clearCookie('connect.sid');
        renderPage(res, 'login', constants.LOGIN_PAGE_TITLE);
    });
};

const verifyToken = async (token) => {
    return new Promise((resolve, reject) => {
        jwt.verify(token, process.env.CONFIRM_MAIL_JWT_SECRET, async (error, decoded) => {
            if (error) {
                reject(error);
            } else {
                resolve(decoded.id);
            }
        });
    });
};

const updateUserEmailStatus = async (userId) => {
    try {
        const result = await User.findByIdAndUpdate(userId, { emailAktif: true });
        return result;
    } catch (error) {
        throw error;
    }
};

const verifyMail = async (req, res, next) => {
    const token = req.query.id;

    if (token) {
        try {
            const userId = await verifyToken(token);
            const result = await updateUserEmailStatus(userId);

            if (result) {
                req.flash('success_message', [{ msg: constants.SUCCESS_MAIL_CONFIRMATION }]);
                res.redirect('/login');
            } 
        } catch (err) {
            console.log('hata çıktı ' + err);
            req.flash('error', constants.ERROR_INVALID_CODE);
            res.redirect('/login');
        }
    }
};

const newSavePassword = (req, res, next) => {
    (async () => {
        try {
            const hatalar = validationResult(req);

            if (!hatalar.isEmpty()) { 
                req.flash('validation_error', hatalar.array());
                req.flash('sifre', req.body.sifre);
                req.flash('resifre', req.body.resifre);
                console.log('formdan gelen değerler');
                console.log(req.body);
                res.redirect(`/reset-password/${req.body.id}/${req.body.token}`);
            } else {
                const _bulunanUser = await User.findOne({ _id: req.body.id, emailAktif:true });
                const secret = process.env.RESET_PASSWORD_JWT_SECRET + "-" + _bulunanUser.sifre;

                const verifyAsync = util.promisify(jwt.verify);
                const decoded = await verifyAsync(req.body.token, secret);

                const hashedPassword = await bcrypt.hash(req.body.sifre, 10);
                const sonuc = await User.findByIdAndUpdate(req.body.id, { sifre : hashedPassword });

                if (sonuc) {
                    req.flash('success_message', [{ msg: constants.SUCCESS_PASSWORD_UPDATE }]);
                } else {
                    req.flash('error', 'Lütfen tekrar şifre sıfırlama adımlarını yapın');
                }

                res.redirect('/login');
            }
        } catch (err) {
            console.log('hata çıktı ' + err);
        }
    })();
};



const ShowNewPasswordForm = async (req, res, next) => {
    const linktekiID = req.params.id;
    const linktekiToken = req.params.token;

    if (linktekiID && linktekiToken) {
        const _bulunanUser = await User.findOne({ _id: linktekiID });
        const secret = process.env.RESET_PASSWORD_JWT_SECRET + "-" + _bulunanUser.sifre;

        try {
            jwt.verify(linktekiToken, secret, async (e, decoded) => {
            
                if (e) {
                    req.flash('error', constants.ERROR_INVALID_CODE);
                    res.redirect('/forget-password');
                } else {
                    res.render('new_password', {id:linktekiID, token:linktekiToken, layout: './layout/auth_layout.ejs', title:'Şifre Güncelle' });
                }
            });
        } catch (err) {
            console.log('hata çıktı ' + err);
        }
    } else {
        req.flash('validation_error', [{msg : constants.VALIDATION_SEND_ERROR}]);
        res.redirect('forget-password');
    }
}

module.exports = {
    showLoginForm,
    showRegisterForm,
    showForgotPasswordForm,
    register,
    login,
    forgetPassword,
    logout,
    verifyMail,
    ShowNewPasswordForm,
    newSavePassword
};