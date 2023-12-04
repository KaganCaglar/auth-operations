const multer = require('multer');
const path = require('path');

const myStorage = multer.diskStorage({
    destination: (req, file, cb) => {
       
        cb(null, path.join(__dirname, "../uploads/avatars"));
    },

    filename: (req, file, cb) => {
      
        cb(null, req.user.email + "" + path.extname(file.originalname));
    }
});

const resimFileFilter = (req, file, cb) => {
    if (file.mimetype == 'image/jpeg' || file.mimetype == 'image/png') {
      
        cb(null, true);
    } else {
    
        cb(null, false);
    }
}

const uploadResim = multer({ storage: myStorage, fileFilter: resimFileFilter});

module.exports = uploadResim;