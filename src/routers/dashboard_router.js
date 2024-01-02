const router = require('express').Router();
const dashboardController = require('../controllers/dashboard_controller');
const authMiddleware = require('../middlewares/auth_middleware');
const multerConfig = require('../config/multer_config');

router.get('/', authMiddleware.sessionOpened, dashboardController.showHomePage);
router.get('/profil', authMiddleware.sessionOpened, dashboardController.showProfilePage);

router.post('/profil-guncelle', authMiddleware.sessionOpened, multerConfig.single('avatar'),  dashboardController.updateProfile);



module.exports = router;