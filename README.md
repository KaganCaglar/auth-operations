# Auth-operations
Bu proje, Express.js kullanarak bir web uygulamasının temelini atmaktadır. MongoDB veritabanı bağlantısı kurulmuş, oturum yönetimi ve kullanıcı kimlik doğrulama işlemleri yapılmıştır.

## Özellikler

- **MongoDB Bağlantısı:** `./src/config/database` üzerinden MongoDB bağlantısı sağlanmıştır.
- **Express ve Temel Ayarlar:** Temel web uygulaması oluşturulmuş, EJS şablon motoru ve layoutlar kullanılmıştır.
- **Session ve Flash Mesajları:** `express-session` ve `connect-flash` kullanılarak oturum yönetimi ve flash mesajları entegre edilmiştir.
- **Passport ve Oturum Kontrolü:** Passport kullanılarak kullanıcı kimlik doğrulama ve oturum kontrolü sağlanmıştır.
- **Routers:** `/` ve `/yonetim` rotaları için ayrı router dosyaları kullanılmıştır.
- **API Endpoint:** `/api` rotası üzerinden basit bir JSON API endpoint oluşturulmuştur.


## Nasıl Kullanılır
- Uygulamayı başlattıktan sonra tarayıcınızda `http://localhost:PORT` adresine giderek uygulamayı kullanabilirsiniz.
- Rotalar ve temel kullanım adımları için `readme` dosyasını inceleyin.


## Kurulum
1. Proje dosyalarınızı bilgisayarınıza klonlayın.
2. Terminal veya komut istemcisinde `npm install` komutunu çalıştırarak bağımlılıkları yükleyin.
3. MongoDB bağlantı bilgilerinizi `.env` dosyasına ekleyin.
4. `npm run dev` komutu ile uygulamayı başlatın.

## .env Dosyası Kullanım
# .env.example

# MongoDB URI
- MONGODB_URI=mongodb+srv://your_username:your_password@your_cluster_url/

# Port number for the server
- PORT=8080

# Session secret key for secure sessions
- SESSION_SECRET=your_session_secret_key

# JSON Web Token (JWT) secret for confirming email addresses
- CONFIRM_MAIL_JWT_SECRET=your_confirm_mail_jwt_secret

# JSON Web Token (JWT) secret for resetting passwords
- RESET_PASSWORD_JWT_SECRET=your_reset_password_jwt_secret

# Website URL
- WEB_SITE_URL=http://localhost:8080/

# Gmail credentials for sending emails
- GMAIL_USER=your_email@gmail.com
- GMAIL_SIFRE=your_gmail_password

# Exposed port for MySQL database (example)
- Expose=3306