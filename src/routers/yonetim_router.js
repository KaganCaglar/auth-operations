const router = require('express').Router();
const yonetimController = require('../controllers/yonetim_controller');
const authMiddleware = require('../middlewares/auth_middleware');
const multerConfig = require('../config/multer_config');

router.get('/', authMiddleware.sessionOpened, yonetimController.showHomePage);
router.get('/profil', authMiddleware.sessionOpened, yonetimController.showProfilePage);

router.post('/profil-guncelle', authMiddleware.sessionOpened, multerConfig.single('avatar'),  yonetimController.updateProfile);



module.exports = router;