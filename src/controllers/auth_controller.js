const { validationResult } = require('express-validator');
const User = require('../model/user_model');
const passport = require('passport');
require('../config/passport_local')(passport);
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const constants = require('./constants');

const renderPage = (res, page, title) => {
    res.render(page, { layout: './layout/auth_layout.ejs', title });
};

const showLoginForm = (req, res, next) => {
    renderPage(res, 'login', constants.LOGIN_PAGE_TITLE);
};

const login = (req, res, next) => {
    const errors = validationResult(req);
    req.flash('email', req.body.email);
    req.flash('sifre', req.body.sifre);
    
    if (!errors.isEmpty()) { 
        req.flash('validation_error', errors.array());
        res.redirect('/login'); 
    } else {
        passport.authenticate('local', {
            successRedirect: '/dashboard',
            failureRedirect: '/login',
            failureFlash: true
        })(req, res, next);
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

// Onay e-postası gönderme fonksiyonu
const sendVerificationEmail = async (email, jwtToken) => {
    const url = process.env.WEB_SITE_URL + 'verify?id=' + jwtToken;
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_SIFRE
        }
    });

    await transporter.sendMail({
        from: 'Nodejs Application <info@nodejskursu.com>',
        to: email,
        subject: 'Please Confirm Your Email',
        text: 'To confirm your email, please click the following link: ' + url
    });
    
};

const register = async (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) { 
        handleRegistrationErrors(req, res, errors);
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
                
                await handleJWTAndMail(newUser, req, res);

                req.flash('success_message', [{ msg: 'You have successfully registered. Please check your email and verify your account.' }]);
                res.redirect('/login');
            }
        } catch (err) {
            console.log('Error occurred while registering user' + err);
        }
    }
};

const handleRegistrationErrors = (req, res, errors) => {
    req.flash('validation_error', errors.array());
    req.flash('email', req.body.email);
    req.flash('name', req.body.name);
    req.flash('surname', req.body.surname);
    req.flash('password', req.body.password);
    req.flash('repassword', req.body.repassword);
    res.redirect('/register');
};

const handleExistingUserError = (req, res) => {
    const validationError = [{msg : constants.VALIDATION_ERROR}];
    req.flash('validation_error', errors.array());
    req.flash('email', req.body.email);
    req.flash('name', req.body.name);
    req.flash('surname', req.body.surname);
    req.flash('password', req.body.password);
    req.flash('repassword', req.body.repassword);
    res.redirect('/register');
};

const createAndSaveNewUser = async (formData) => {
    const { email: userEmail, ad, soyad, sifre: rawPassword } = formData;
    const hashedSifre = await bcrypt.hash(rawPassword, 10);

    const newUser = new User({
        email: userEmail,
        ad,
        soyad,
        sifre: hashedSifre
    });

    return await newUser.save();
};

const handleJWTAndMail = async (newUser, req, res) => {
    const { id, email } = newUser;
    const jwtBilgileri = {
        id,
        mail: email
    };

    const jwtToken = jwt.sign(jwtBilgileri, process.env.CONFIRM_MAIL_JWT_SECRET, { expiresIn: '1d' });

    const url = process.env.WEB_SITE_URL + 'verify?id=' + jwtToken;
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.GMAIL_USER,
            pass: process.env.GMAIL_SIFRE
        }
    });

    await transporter.sendMail({
        from: 'Node.js Application <info@nodejskursu.com>',
        to: newUser.email,
        subject: 'Please Confirm Your Email',
        text: 'To confirm your email, please click the following link: ' + url
        
    });
};

const forgetPasswordFormunuGoster = (req, res, next) => {
    renderPage(res, 'forget_password', constants.FORGET_PASSWORD_PAGE_TITLE);
};
const forgetPassword = async (req, res, next) => {

    const errors = validationResult(req);

    if (!errors.isEmpty()) { 

        req.flash('validation_error', errors.array());
        req.flash('email', req.body.email);
      
        res.redirect('/forget-password');
    }
    const generateJWT = (user) => {
        const jwtBilgileri = {
            id: user.id,
            mail: user.email
        };
        return jwt.sign(jwtBilgileri, process.env.CONFIRM_MAIL_JWT_SECRET, { expiresIn: '1d' });
    };
    
    const sendVerificationEmail = async (email, jwtToken) => {
        const url = process.env.WEB_SITE_URL + 'verify?id=' + jwtToken;
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.GMAIL_USER,
                pass: process.env.GMAIL_SIFRE
            }
        });
    
        await transporter.sendMail({
            from: 'Node.js Application <info@nodejskursu.com>',
        to: email,
        subject: 'Please Confirm Your Email',
        text: 'To confirm your email, please click the following link: ' + url

        });
    };
    
    const register = async (req, res, next) => {
        const errors = validationResult(req);
        
        if (!errors.isEmpty()) { 
            req.flash('validation_error', errors.array());
            req.flash('email', req.body.email);
            req.flash('name', req.body.name);
            req.flash('surname', req.body.surname);
            req.flash('password', req.body.password);
            req.flash('repassword', req.body.repassword);
            res.redirect('/register');

        } else {
            try {
                const existingUser = await User.findOne({ email: req.body.email });
                
                if (existingUser && existingUser.emailAktif) {
                    const validationError = [{msg : constants.VALIDATION_ERROR}];
                    req.flash('validation_error', validationError);
                    req.flash('email', req.body.email);
                    req.flash('name', req.body.name);
                    req.flash('surname', req.body.surname);
                    req.flash('password', req.body.password);
                    req.flash('repassword', req.body.repassword);
                    res.redirect('/register');
                } else {
                    if (existingUser) { 
                        await User.findByIdAndRemove({ _id: existingUser._id });
                    }
                    
                    const newUser = new User({
                        email: req.body.email,
name: req.body.name,
surname: req.body.surname,
password: await bcrypt.hash(req.body.password, 10)

                    });
                    
                    await newUser.save();
    
                    // JWT işlemleri
                    const jwtToken = generateJWT(newUser);
    
                    // Mail gönderme işlemleri
                    await sendVerificationEmail(newUser.email, jwtToken);
    
                    req.flash('success_message', [{ msg: 'You have successfully registered. Please check your email and verify your account.' }]);
                    res.redirect('/login');
                }
            } catch (err) {
                console.log('Error occurred while registering user' + err);
            }
        }
    };
    
};

const logout = (req, res, next) => {
    req.logout();
    req.session.destroy((error) => {
        res.clearCookie('connect.sid');
        renderPage(res, 'login', constants.LOGIN_PAGE_TITLE);
    });
};

const verifyMail = async (req, res, next) => {
    const token = req.query.id;

    if (token) {
        try {
            jwt.verify(token, process.env.CONFIRM_MAIL_JWT_SECRET, async (e, decoded) => {
                if (e) {
                    req.flash('error', constants.ERROR_INVALID_CODE);
                    res.redirect('/login');
                } else {
                    const tokenIcindekiIDDegeri = decoded.id;
                    const sonuc = await User.findByIdAndUpdate(tokenIcindekiIDDegeri, { emailAktif: true });

                    if (sonuc) {
                        req.flash('success_message', [{ msg: constants.SUCCESS_MAIL_CONFIRMATION }]);
                        res.redirect('/login');
                    } else {
                        req.flash('error', constants.ERROR_CREATE_USER);
                        res.redirect('/login');
                    }
                }
            });
        } catch (err) {
            console.log('error occurred ' + err);
        }
    }
};

const newSavePassword = async (req, res, next) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) { 
        req.flash('validation_error', errors.array());
        req.flash('password', req.body.sifre);
        req.flash('rePassword', req.body.resifre);
        console.log('values ​​from form');
        console.log(req.body);
        res.redirect('/reset-password/'+req.body.id+"/"+req.body.token);
    } else {
        const _foundUser = await User.findOne({ _id: req.body.id, emailAktif:true });
        const secret = process.env.RESET_PASSWORD_JWT_SECRET + "-" + _foundUser.sifre;

        try {
            jwt.verify(req.body.token, secret, async (e, decoded) => {
            
                if (e) {
                    req.flash('error', 'Code is invalid or has expired.');
                    res.redirect('/forget-password');
                } else {
                    const hashedPassword = await bcrypt.hash(req.body.sifre, 10);
                    const sonuc = await User.findByIdAndUpdate(req.body.id, { sifre : hashedPassword });
            
                    if (sonuc) {
                        req.flash('success_message', [{ msg: constants.SUCCESS_PASSWORD_UPDATE }]);
                    } else {
                        req.flash('error', 'Please do the password reset steps again');
                    }
                    res.redirect('/login');
                }
            });
        } catch (err) {
            console.log('error occurred' + err);
        }
    }
};

const showNewPasswordForm = async (req, res, next) => {
    const linkID = req.params.id;
    const tokenİnTheLink = req.params.token;

    if (linkID && tokenİnTheLink) {
        const _foundUser = await User.findOne({ _id: linkID });
        const secret = process.env.RESET_PASSWORD_JWT_SECRET + "-" + _foundUser.sifre;

        try {
            jwt.verify(tokenİnTheLink, secret, async (e, decoded) => {
            
                if (e) {
                    req.flash('error', constants.ERROR_INVALID_CODE);
                    res.redirect('/forget-password');
                } else {
                    res.render('new_password', {id:linkID, token:tokenİnTheLink, layout: './layout/auth_layout.ejs', title:'Update Password                    ' });
                }
            });
        } catch (err) {
            console.log('error occurred' + err);
        }
    } else {
        req.flash('validation_error', [{msg : constants.VALIDATION_SEND_ERROR}]);
        res.redirect('forget-password');
    }
}

module.exports = {
  showLoginForm,
  showRegisterForm,
    forgetPasswordFormunuGoster,
    register,
    login,
    forgetPassword,
    logout,
    verifyMail,
    showNewPasswordForm,
    newSavePassword
};
