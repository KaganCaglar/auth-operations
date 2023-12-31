# Auth-operations
Bu proje, Express.js kullanarak bir web uygulamasının temelini atmaktadır. MongoDB veritabanı bağlantısı kurulmuş, oturum yönetimi ve kullanıcı kimlik doğrulama işlemleri yapılmıştır.

## Özellikler

- **MongoDB Bağlantısı:** `./src/config/database` üzerinden MongoDB bağlantısı sağlanmıştır.
- **Express ve Temel Ayarlar:** Temel web uygulaması oluşturulmuş, EJS şablon motoru ve layoutlar kullanılmıştır.
- **Session ve Flash Mesajları:** `express-session` ve `connect-flash` kullanılarak oturum yönetimi ve flash mesajları entegre edilmiştir.
- **Passport ve Oturum Kontrolü:** Passport kullanılarak kullanıcı kimlik doğrulama ve oturum kontrolü sağlanmıştır.
- **Routers:** `/` ve `/admin` rotaları için ayrı router dosyaları kullanılmıştır.
- **API Endpoint:** `/api` rotası üzerinden basit bir JSON API endpoint oluşturulmuştur.


## Nasıl Kullanılır
- Uygulamayı başlattıktan sonra tarayıcınızda `http://localhost:PORT` adresine giderek uygulamayı kullanabilirsiniz.
- Rotalar ve temel kullanım adımları için `readme` dosyasını inceleyin.


## Kurulum
1. Proje dosyalarınızı bilgisayarınıza klonlayın.
2. Terminal veya komut istemcisinde `npm install` komutunu çalıştırarak bağımlılıkları yükleyin.
3. MongoDB bağlantı bilgilerinizi `.env` dosyasına ekleyin.(`.env.example` içinde örnek var.)
4. `npm run dev` komutu ile uygulamayı başlatın.


