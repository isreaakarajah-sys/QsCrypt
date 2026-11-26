plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// CI provides these; locally the release build falls back to the debug key.
val keystorePath: String? = System.getenv("QS_KEYSTORE_PATH")
val buildNumber: Int = System.getenv("GITHUB_RUN_NUMBER")?.toIntOrNull() ?: 1

android {
    namespace = "com.qscrypt.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.qscrypt.app"
        // Android 7.0 and later (APK signature scheme v2 only, no JAR signing).
        minSdk = 24
        targetSdk = 35
        versionCode = buildNumber
        versionName = "1.0.$buildNumber"
    }

    // One APK per phone generation, plus one that runs everywhere:
    // arm64-v8a for phones of the last ~8 years, armeabi-v7a for older
    // 32-bit phones, and a universal APK with every engine build.
    splits {
        abi {
            isEnable = true
            reset()
            include("arm64-v8a", "armeabi-v7a")
            isUniversalApk = true
        }
    }

    signingConfigs {
        create("release") {
            if (keystorePath != null) {
                storeFile = file(keystorePath)
                storePassword = System.getenv("QS_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("QS_KEY_ALIAS")
                keyPassword = System.getenv("QS_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (keystorePath != null) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    lint {
        // Only what would crash an older phone is checked (CI runs it), and it must pass.
        checkOnly += "NewApi"
        checkReleaseBuilds = false
        abortOnError = true
        textReport = true
        textOutput = file("stdout")
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    // QR codes for identity cards (encoding and decoding only; no camera library).
    implementation("com.google.zxing:core:3.5.3")
}
