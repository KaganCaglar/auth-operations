const router = require('express').Router();
const authController = require('../controllers/auth_controller');
const validatorMiddleware = require('../middlewares/validation_middleware');
const authMiddleware = require('../middlewares/auth_middleware');


router.get('/login', authMiddleware.notLoggedIn, authController.renderLoginForm);
router.post('/login', authMiddleware.notLoggedIn, validatorMiddleware.validateLogin(), authController.login);

router.get('/register', authMiddleware.notLoggedIn, authController.renderRegisterForm);
router.post('/register', authMiddleware.notLoggedIn, validatorMiddleware.validateNewUser(), authController.register);

router.get('/forget-password',authMiddleware.notLoggedIn, authController.renderForgotPasswordForm);
router.post('/forget-password', authMiddleware.notLoggedIn, validatorMiddleware.validateEmail(), authController.forgetPassword);

router.get('/verify', authController.verifyMail);


router.get('/reset-password/:id/:token', authController.renderNewPasswordForm);
router.get('/reset-password', authController.renderNewPasswordForm);
router.post('/reset-password', validatorMiddleware.validateNewPassword(), authController.saveNewPassword);
router.get('/logout', authMiddleware.sessionOpened, authController.logout);


module.exports = router;