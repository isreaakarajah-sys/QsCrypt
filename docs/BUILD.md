# بناء QsCrypt من السورس

## الأدوات

- Rust (stable) مع أهداف أندرويد:
  `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android`
- `cargo install cargo-ndk`
- Android NDK r27c، وAndroid SDK (compileSdk 35)، وJDK 17.
- Python 3 لأدوات الإصدار، و`apksigner` من Android build-tools.

## 1. اختبار المحرك

```sh
cd core && cargo test --workspace --release
```

## 2. بناء المحرك لأندرويد

```sh
cd core
export ANDROID_NDK_HOME=/path/to/android-ndk-r27c
cargo ndk --platform 24 -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
  -o ../android/app/src/main/jniLibs build --release -p qscrypt-ffi
```

## 3. بناء ملفات APK

```sh
cd android
export QS_KEYSTORE_PATH=/path/to/qscrypt-release.jks
export QS_KEYSTORE_PASSWORD="$(cat QS_KEYSTORE_PASSWORD.txt)"
export QS_KEY_ALIAS="$(cat QS_KEY_ALIAS.txt)"
export QS_KEY_PASSWORD="$(cat QS_KEY_PASSWORD.txt)"
./gradlew assembleRelease
```

الملفات الثلاثة في `android/app/build/outputs/apk/release/`:
`app-universal-release.apk` و`app-arm64-v8a-release.apk` و`app-armeabi-v7a-release.apk`.

الطريق الأسهل: كل دفع إلى الفرع `main` يبني الملفات الثلاثة تلقائياً على GitHub، في صفحة **Releases**.

## 4. خطوة لا بد منها قبل التوزيع: ملف الفلفل

الملفات الخارجة من الخطوة 3، أو من GitHub، **لا تقبل رمز التفعيل بعد**. خطوط التطبيق مقفلة بمفتاح يُشتق من رمز التفعيل ومن سرّ إضافي طوله 32 بايت. هذا السرّ ليس في السورس، وإنما في الملف `QS_ACTIVATION_PEPPER.txt` ضمن مجموعة التوقيع. الأداة `pepper.py` تكتبه داخل مكتبة المحرك في الملف، ثم يُعاد التوقيع لأن التوقيع القديم لم يعد يطابق:

```sh
python3 android/tools/pepper.py app-universal-release.apk QsCrypt-universal.apk \
  --pepper-file QS_ACTIVATION_PEPPER.txt
apksigner sign --ks qscrypt-release.jks --ks-key-alias "$(cat QS_KEY_ALIAS.txt)" \
  --ks-pass file:QS_KEYSTORE_PASSWORD.txt --key-pass file:QS_KEY_PASSWORD.txt \
  QsCrypt-universal.apk
apksigner verify --print-certs QsCrypt-universal.apk
```

كرّر الخطوة لكل ملف من الثلاثة. ووقّع دائماً بالمفتاح نفسه، وإلا لن يُركَّب التحديث فوق النسخة الموجودة على الجوال.

## الأسرار لا تُرفع إلى GitHub أبداً

المستودع عام، فتبقى مجموعة التوقيع خارجه وفي مكان آمن، ويشمل ذلك المفتاح وكلمات سرّه وملف الفلفل.

- **إن ضاع المفتاح:** لن يُركَّب أي تحديث فوق النسخة الموجودة.
- **إن ضاع ملف الفلفل:** لن تقبل أي نسخة جديدة رمز التفعيل.

## اختبارات التوافق

ملف العمل `.github/workflows/compat.yml` يشغّل الاختبارات الآتية:

- **مقابل أدوات لينكس:** أنظمة الملفات (FAT وexFAT وNTFS)، وحاويات VeraCrypt وBitLocker.
- **على ويندوز حقيقي:** يشغّل chkdsk على أقراص NTFS كتبها التطبيق، ثم يكتب ويندوز عليها ويكمل التطبيق الكتابة.

السكربتات في `core/testdata/`، وأداة الفحص `core/crates/qscrypt-core/examples/fsprobe.rs`.
