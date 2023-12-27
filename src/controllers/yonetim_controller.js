const User = require('../model/user_model');

const showHomePage = function (req, res, next) {
    res.render('index', { layout: './layout/dashboard_layout.ejs', title:'Yönetim Paneli Ana Sayfa' });
};

const showProfilePage = function (req, res, next) {
    res.render('profil', { user:req.user, layout: './layout/dashboard_layout.ejs', title:'ProfilSayfası' });
};

const updateProfile = async function (req, res, next) {
    const { firstName, lastName, file } = req.body;

    const currentInformation = {
        firstName,
        lastName,
    };

    try {
        if (file) {
            currentInformation.avatar = file.filename;
        }

        const result = await User.findByIdAndUpdate(req.user.id, currentInformation);

        if (result) {
            console.log("Update completed");
            res.redirect('/dashboard/profile');
        }

    } catch (error) {
        console.log(error);
    }
};

module.exports = {
    showHomePage,
    showProfilePage,
    updateProfile
};
