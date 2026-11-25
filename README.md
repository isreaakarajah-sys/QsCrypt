# QsCrypt

**خزنتك المشفّرة على Android وسطح المكتب.**

- يفتح ويُنشئ حاويات وأقراصاً بصيغ **VeraCrypt** و**TrueCrypt** و**BitLocker**.
- له صيغته الخاصة **QsCrypt**: تشفير بثلاث طبقات (AES-256 ← Twofish-256 ← XChaCha20-Poly1305) مع Argon2id، ومشاركة مربوطة بالأجهزة مقاومة للحوسبة الكمومية.

> مشروع خاص، قيد التطوير. لا يتصل بالإنترنت ولا يطلب صلاحية `INTERNET`.

## ما يعمل الآن (نسخة تجريبية 0.1)

- فتح حاويات VeraCrypt وTrueCrypt، العادية والمخفية، بكل الخوارزميات الشائعة وسلاسلها، من الجوال أو من فلاشة.
- تصفّح FAT وexFAT، والكتابة على FAT، وعرض الصور والنصوص داخل التطبيق.
- إنشاء حاويات VeraCrypt وTrueCrypt.
- تشفير الملفات بصيغة QsCrypt وفكّها.
- قفل التطبيق برمز سري، ومنع لقطات الشاشة.

## الوثائق

- [وثيقة المتطلبات](docs/REQUIREMENTS.md)
- [سجل التقدم](docs/PROGRESS.md)

## بنية المستودع

| المجلد | المحتوى |
|---|---|
| `core/crates/qscrypt-core` | المحرك بلغة Rust: الصيغ وأنظمة الملفات، دون اعتماديات |
| `core/crates/qscrypt-crypto` | خوارزميات الإنتاج (RustCrypto) |
| `core/crates/qscrypt-ffi` | طبقة الربط مع Android (JNI) |
| `core/testdata` | متجهات وحاويات اختبار مولّدة بتطبيق Python مستقل |
| `android/` | تطبيق Android بـ Kotlin وJetpack Compose |
| `brand/` | ملفات الهوية البصرية |
| `.github/workflows/` | البناء والاختبار التلقائي |

## الاختبارات

```sh
cd core && cargo test --workspace --release
python3 core/testdata/gen_vectors.py   # يعيد توليد المتجهات وحاويات الاختبار
```

## الحصول على التطبيق

كل تعديل على الفرع `main` يبني تلقائياً ملف APK موقّعاً. يمكنك تنزيله من صفحة **Releases**، ثم تركيبه على الجوال بعد السماح بتثبيت التطبيقات من مصادر خارجية.
