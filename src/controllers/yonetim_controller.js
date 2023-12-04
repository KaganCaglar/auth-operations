const User = require('../model/user_model');

const anaSayfayiGoster = function (req, res, next) {
    res.render('index', { layout: './layout/yonetim_layout.ejs', title:'Yönetim Paneli Ana Sayfa' });
}

const profilSayfasiniGoster = function (req,res,next) {
   
    res.render('profil', { user:req.user, layout: './layout/yonetim_layout.ejs', title:'ProfilSayfası' });
}

const profilGuncelle = async function (req, res, next) {
    const { ad, soyad, file } = req.body

    const guncelBilgiler = {
        ad,
        soyad,
    };

    try {
        if (file) {
            guncelBilgiler.avatar = file.filename;
        }

        const sonuc = await User.findByIdAndUpdate(req.user.id, guncelBilgiler);

        if (sonuc) {
            console.log("update tamamlandı");
            res.redirect('/yonetim/profil');
        }
        
    } catch (hata) {
        console.log(hata);
    }
};

module.exports = {
    anaSayfayiGoster,
    profilSayfasiniGoster,
    profilGuncelle
}