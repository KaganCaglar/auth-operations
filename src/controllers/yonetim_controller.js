const User = require('../model/user_model');

const showHomePage = function (req, res, next) {
    res.render('index', { layout: './layout/yonetim_layout.ejs', title:'Yönetim Paneli Ana Sayfa' });
}

const showProfilePage = function (req,res,next) {
   
    res.render('profil', { user:req.user, layout: './layout/yonetim_layout.ejs', title:'ProfilSayfası' });
}

const updateProfile = async function (req, res, next) {
    const { ad, soyad, file } = req.body

    const currentInformation = {
        ad,
        soyad,
    };

    try {
        if (file) {
            currentInformation.avatar = file.filename;
        }

        const sonuc = await User.findByIdAndUpdate(req.user.id, currentInformation);

        if (sonuc) {
            console.log("update tamamlandı");
            res.redirect('/yonetim/profil');
        }
        
    } catch (hata) {
        console.log(hata);
    }
};

module.exports = {
    showHomePage,
    showProfilePage,
    updateProfile
}