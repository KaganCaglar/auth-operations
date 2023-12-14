const LocalStrategy = require('passport-local').Strategy;
const User = require('../model/user_model');
const bcrypt = require('bcrypt');

module.exports = function (passport) {
    const options = {
        usernameField: 'email',
        passwordField: 'sifre'
    };

    passport.use(new LocalStrategy(options, async (email, sifre, done) => {
        try {
            const _bulunanUser = await User.findOne({ email: email });

            // isUserExist fonksiyonunu çağırırken done fonksiyonunu parametre olarak geçirin
            isUserExist(_bulunanUser, done);

            const sifreKontrol = await bcrypt.compare(sifre, _bulunanUser.sifre);
            if (!sifreKontrol) {
                return done(null, false, { message: 'Şifre hatalı' });
            } else {
                if (_bulunanUser && _bulunanUser.emailAktif === false) {
                    return done(null, false, { message: 'Lütfen emailiniz onaylayın' });
                } else {
                    return done(null, _bulunanUser);
                }
            }
        } catch (err) {
            return done(err);
        }
    }));

    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function (id, done) {
        User.findById(id, function (err, user) {
            if (err || !user) {
                return done(err, null);
            }

            const { id, email, ad, soyad, sifre, createdAt, avatar } = user;

            const yeniUser = {
                id,
                email,
                ad,
                soyad,
                sifre,
                olusturulmaTarihi: createdAt,
                avatar
            };

            done(null, yeniUser);
        });
    });

    // isUserExist fonksiyonunu, done parametresini kullanarak düzenleyin
    async function isUserExist(user, done) {
        if (!user) {
            return done(null, false, { message: 'User bulunamadı' });
        }

        // Eğer kullanıcı bulunduysa, işlemlerinizi buraya ekleyebilirsiniz.
        // Örneğin, kullanıcının varlığı durumunda başka bir şeyler yapabilirsiniz.
    }
}
