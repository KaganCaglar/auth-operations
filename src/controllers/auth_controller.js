const { validationResult } = require('express-validator');
const winston = require('winston');
const constants = require('./constants');
const User = require('../model/user_model');
const passport = require('passport');
require('../config/passport_local')(passport);
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const util = require('util');

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logfile.log' }),
  ],
  format: winston.format.combine(winston.format.timestamp(), winston.format.simple()),
});

const hashPassword = async (password) => {
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    return hashedPassword;
  } catch (error) {
    logger.error(constants.OTHER_MESSAGES.HASHING_ERROR, error);
    throw error;
  }
};

const renderPage = (res, page, title) => res.render(page, { layout: './layout/auth_layout.ejs', title });
const renderAuthPage = (res, page, pageTitle) => renderPage(res, page, pageTitle);
const renderLoginForm = (req, res, next) => renderAuthPage(res, 'login', constants.PAGE_TITLES.LOGIN);

const setFlashMessages = (req, errors) => {
  req.flash('email', req.body.email);
  req.flash('sifre', req.body.sifre);
  req.flash('validation_error', errors.array());
};

const handleAuthentication = (req, res, next) => passport.authenticate('local', { successRedirect: '/yonetim', failureRedirect: '/login', failureFlash: true })(req, res, next);

const login = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    setFlashMessages(req, errors);
    res.redirect('/login');
  } else {
    handleAuthentication(req, res, next);
  }
};

const renderRegisterForm = (req, res, next) => renderAuthPage(res, 'register', constants.PAGE_TITLES.REGISTER);

const generateJWT = (user) => jwt.sign({ id: user.id, mail: user.email }, process.env.CONFIRM_MAIL_JWT_SECRET, { expiresIn: '1d' });

const createTransporter = () => {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_SIFRE }
  });
};

const sendEmail = async (options) => {
  try {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_SIFRE
      }
    });

    await transporter.sendMail(options);

    logger.info(constants.OTHER_MESSAGES.EMAIL_SENT_SUCCESS);
  } catch (error) {
    logger.error(constants.OTHER_MESSAGES.EMAIL_SEND_ERROR, error);
    throw error;
  }
};

const handleRegistrationErrors = (req, res, errors) => {
  const fields = ['email', 'ad', 'soyad', 'sifre', 'resifre'];
  req.flash('validation_error', errors.array());
  fields.forEach(field => req.flash(field, req.body[field]));
  res.redirect('/register');
};

const handleExistingUserError = (req, res) => {
  const validationError = [{ msg: constants.VALIDATION_ERRORS }];
  const fields = ['email', 'ad', 'soyad', 'sifre', 'resifre'];
  req.flash('validation_error', validationError);
  fields.forEach(field => req.flash(field, req.body[field]));
  res.redirect('/register');
};

const create = async (formData) => {
  const { email: userEmail, ad, soyad, sifre: rawSifre } = formData;
  const hashedSifre = await bcrypt.hash(rawSifre, 10);
  return await new User({ email: userEmail, ad, soyad, sifre: hashedSifre }).save();
};

const sendVerification = async (newUser, req, res) => {
  try {
    const { id, email } = newUser;
    const jwtToken = generateJWT(newUser);
    const url = process.env.WEB_SITE_URL + 'verify?id=' + jwtToken;

    const sendOptions = {
      to: email,
      from: 'Nodejs Uygulaması <info@nodejskursu.com>',
      subject: constants.EMAIL_SUBJECTS.CONFIRMATION,
      text: constants.EMAIL_MESSAGES.CONFIRMATION_TEXT + ' ' + url
    };

    await sendEmail(sendOptions);

    req.flash('success_message', [{ msg: 'Kaydınız başarıyla oluşturuldu. Lütfen e-postanızı kontrol edin ve hesabınızı onaylayın.' }]);
    res.redirect('/login');
  } catch (error) {
    logger.error(constants.OTHER_MESSAGES.EMAIL_SEND_ERROR, error);
    req.flash('error', constants.OTHER_MESSAGES.UNEXPECTED_ERROR);
    res.redirect('/register');
  }
};

const renderForgotPasswordForm = (req, res, next) => renderAuthPage(res, 'forget_password', constants.PAGE_TITLES.FORGET_PASSWORD);

const forgetPassword = async (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    req.flash('validation_error', errors.array());
    req.flash('email', req.body.email);
    res.redirect('/forget-password');
  } else {
    try {
      await handleForgetPassword(req, res);
    } catch (err) {
      logger.error(constants.OTHER_MESSAGES.USER_SAVE_ERROR + ' ' + err);
    }
  }
};

const handleForgetPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email, emailAktif: true });

    if (!user) {
      req.flash('validation_error', [{ msg: constants.FLASH_MESSAGES.INVALID_EMAIL_OR_INACTIVE_USER }]);
      req.flash('email', req.body.email);
      return res.redirect('/forget-password');
    }

    const jwtToken = jwt.sign({ id: user._id, mail: user.email }, process.env.RESET_PASSWORD_JWT_SECRET + "-" + user.sifre, { expiresIn: '1d' });

    const resetPasswordUrl = process.env.WEB_SITE_URL + 'reset-password/' + user._id + "/" + jwtToken;

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_SIFRE }
    });

    const mailOptions = {
      from: 'Nodejs Uygulaması <info@nodejskursu.com>',
      to: user.email,
      subject: constants.EMAIL_SUBJECTS.PASSWORD_UPDATE,
      text: constants.EMAIL_MESSAGES.PASSWORD_UPDATE_TEXT + ' ' + resetPasswordUrl
    };

    await transporter.sendMail(mailOptions);

    logger.info(constants.OTHER_MESSAGES.UPDATE_EMAIL_SENT_SUCCESS);
    req.flash('success_message', [{ msg: constants.FLASH_MESSAGES.SUCCESS_MAIL_CHECK }]);
    res.redirect('/login');
  } catch (error) {
    logger.error(constants.OTHER_MESSAGES.EMAIL_SEND_ERROR, error);
    req.flash('error', constants.OTHER_MESSAGES.UNEXPECTED_ERROR);
    res.redirect('/forget-password');
  }
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

        const newUser = await create(req.body);

        await sendVerification(newUser, req, res);
        logger.info(constants.OTHER_MESSAGES.EMAIL_SENT_SUCCESS);
        res.redirect('/login');
      }
    } catch (err) {
      logger.error(err);
    }
  }
};

const logout = (req, res, next) => {
  req.logout();
  req.session.destroy((error) => {
    res.clearCookie('connect.sid');
    renderAuthPage(res, 'login', constants.PAGE_TITLES.LOGIN);
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
        req.flash('success_message', [{ msg: constants.FLASH_MESSAGES.SUCCESS_MAIL_CONFIRMATION }]);
        res.redirect('/login');
      }
    } catch (err) {
      logger.error(constants.OTHER_MESSAGES.CODE_ERROR + ' ' + err);
      req.flash('error', constants.FLASH_MESSAGES.ERROR_INVALID_CODE);
      res.redirect('/login');
    }
  }
};

const saveNewPassword = (req, res, next) => {
  (async () => {
    try {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        req.flash('validation_error', errors.array());
        req.flash('sifre', req.body.sifre);
        req.flash('resifre', req.body.resifre);
        logger.info(constants.OTHER_MESSAGES.FORM_VALUES);
        logger.info(req.body);
        res.redirect(`/reset-password/${req.body.id}/${req.body.token}`);
      } else {
        const _bulunanUser = await User.findOne({ _id: req.body.id, emailAktif: true });
        const secret = process.env.RESET_PASSWORD_JWT_SECRET + "-" + _bulunanUser.sifre;

        const verifyAsync = util.promisify(jwt.verify);
        const decoded = await verifyAsync(req.body.token, secret);

        const hashedPassword = await hashPassword(req.body.sifre);
        const sonuc = await User.findByIdAndUpdate(req.body.id, { sifre: hashedPassword });

        if (sonuc) {
          req.flash('success_message', [{ msg: constants.FLASH_MESSAGES.SUCCESS_PASSWORD_UPDATE }]);
        }

        res.redirect('/login');
      }
    } catch (err) {
      logger.error(constants.OTHER_MESSAGES.CODE_ERROR + ' ' + err);
    }
  })();
};

const renderNewPasswordForm = async (req, res, next) => {
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
          renderPage(res, 'new_password', { id: linktekiID, token: linktekiToken, layout: './layout/auth_layout.ejs', title: 'Şifre Güncelle' });
        }
      });
    } catch (err) {
      logger.error('hata çıktı ' + err);
    }
  } else {
    req.flash('validation_error', [{ msg: constants.VALIDATION_SEND_ERROR }]);
    res.redirect('forget-password');
  }
};

module.exports = {
  renderLoginForm,
  renderRegisterForm,
  renderForgotPasswordForm,
  register,
  login,
  forgetPassword,
  logout,
  verifyMail,
  renderNewPasswordForm,
  saveNewPassword
};
