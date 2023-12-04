const router = require('express').Router();
const yonetimController = require('../controllers/yonetim_controller');
const authMiddleware = require('../middlewares/auth_middleware');
const multerConfig = require('../config/multer_config');

router.get('/', authMiddleware.oturumAcilmis, yonetimController.anaSayfayiGoster);
router.get('/profil', authMiddleware.oturumAcilmis, yonetimController.profilSayfasiniGoster);

router.post('/profil-guncelle', authMiddleware.oturumAcilmis, multerConfig.single('avatar'),  yonetimController.profilGuncelle);



module.exports = router;