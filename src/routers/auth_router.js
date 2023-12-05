const router = require('express').Router();
const authController = require('../controllers/auth_controller');
const validatorMiddleware = require('../middlewares/validation_middleware');
const authMiddleware = require('../middlewares/auth_middleware');


router.get('/login', authMiddleware.oturumAcilmamis, authController.showLoginForm);
router.post('/login', authMiddleware.oturumAcilmamis, validatorMiddleware.validateLogin(), authController.login);

router.get('/register', authMiddleware.oturumAcilmamis, authController.showRegisterForm);
router.post('/register', authMiddleware.oturumAcilmamis, validatorMiddleware.validateNewUser(), authController.register);

router.get('/forget-password',authMiddleware.oturumAcilmamis, authController.showForgotPasswordForm);
router.post('/forget-password', authMiddleware.oturumAcilmamis, validatorMiddleware.validateEmail(), authController.forgetPassword);

router.get('/verify', authController.verifyMail);


router.get('/reset-password/:id/:token', authController.ShowNewPasswordForm);
router.get('/reset-password', authController.ShowNewPasswordForm);
router.post('/reset-password', validatorMiddleware.validateNewPassword(), authController.newSavePassword);
router.get('/logout', authMiddleware.oturumAcilmis, authController.logout);


module.exports = router;