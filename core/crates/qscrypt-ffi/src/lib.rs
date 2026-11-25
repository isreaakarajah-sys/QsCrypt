//! JNI entry points for `com.qscrypt.app.QsCore`.
//!
//! Conventions:
//! - Most calls return a JSON string: `{"ok":true,...}` or
//!   `{"ok":false,"code":"wrong_password","message":"..."}`.
//! - File descriptors come from Android's Storage Access Framework; the
//!   engine duplicates them, so the app closes its own copy right away.
//! - Open volumes live in a registry and are addressed by a handle.
//! - Long operations call `Progress.onProgress(done, total): Boolean`;
//!   returning false cancels.
//! - Panics are caught and reported as errors instead of crashing the app.

mod api;

use jni::objects::{JByteArray, JObject, JString, JValue};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

pub use api::*;

fn to_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut())
}

fn get_string(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|j| j.into()).unwrap_or_default()
}

fn get_bytes(env: &mut JNIEnv, a: &JByteArray) -> qscrypt_core::util::Secret {
    match env.convert_byte_array(a) {
        Ok(mut v) => {
            let s = qscrypt_core::util::Secret::from_slice(&v);
            qscrypt_core::util::wipe(&mut v);
            s
        }
        Err(_) => qscrypt_core::util::Secret::default(),
    }
}

/// Runs `f`, turning a panic into an error JSON.
fn guarded(f: impl FnOnce() -> String) -> String {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(s) => s,
        Err(p) => {
            let msg = p.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| p.downcast_ref::<String>().cloned()).unwrap_or_default();
            api::err_json("internal", &format!("engine error: {msg}"))
        }
    }
}

/// Bridges engine progress to a Kotlin `Progress` callback, at most ~10 calls a second.
struct JProgress<'a, 'local> {
    env: &'a mut JNIEnv<'local>,
    cb: &'a JObject<'local>,
    last: Option<Instant>,
}

impl<'a, 'local> JProgress<'a, 'local> {
    fn new(env: &'a mut JNIEnv<'local>, cb: &'a JObject<'local>) -> Self {
        JProgress { env, cb, last: None }
    }

    fn report(&mut self, done: u64, total: u64) -> bool {
        if self.cb.is_null() {
            return true;
        }
        let now = Instant::now();
        if done < total && self.last.is_some_and(|t| now.duration_since(t) < Duration::from_millis(100)) {
            return true;
        }
        self.last = Some(now);
        let r = self
            .env
            .call_method(self.cb, "onProgress", "(JJ)Z", &[JValue::Long(done as i64), JValue::Long(total as i64)])
            .and_then(|v| v.z());
        match r {
            Ok(keep_going) => keep_going,
            Err(_) => {
                let _ = self.env.exception_clear();
                false
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_version<'local>(mut env: JNIEnv<'local>, _this: JObject<'local>) -> jstring {
    to_jstring(&mut env, qscrypt_core::version())
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_selfTest<'local>(mut env: JNIEnv<'local>, _this: JObject<'local>) -> jstring {
    let json = guarded(api::self_test);
    to_jstring(&mut env, &json)
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_com_qscrypt_app_QsCore_openVolume<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    fd: jint,
    password: JByteArray<'local>,
    pim: jint,
    prf: jint,
    format: jint,
    read_only: jboolean,
    tz_minutes: jint,
) -> jstring {
    let pw = get_bytes(&mut env, &password);
    let json = guarded(|| api::open_volume(fd, &pw, pim.max(0) as u32, prf.max(0) as u32, format, read_only != 0, tz_minutes));
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_closeVolume<'local>(_env: JNIEnv<'local>, _this: JObject<'local>, handle: jlong) {
    let _ = catch_unwind(|| api::close_volume(handle));
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_closeAll<'local>(_env: JNIEnv<'local>, _this: JObject<'local>) {
    let _ = catch_unwind(api::close_all);
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_volumeInfo<'local>(mut env: JNIEnv<'local>, _this: JObject<'local>, handle: jlong) -> jstring {
    let json = guarded(|| api::volume_info(handle));
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_list<'local>(mut env: JNIEnv<'local>, _this: JObject<'local>, handle: jlong, path: JString<'local>) -> jstring {
    let path = get_string(&mut env, &path);
    let json = guarded(|| api::list(handle, &path));
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_readFile<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
    path: JString<'local>,
    max_bytes: jlong,
) -> jbyteArray {
    let path = get_string(&mut env, &path);
    let data = catch_unwind(|| api::read_file(handle, &path, max_bytes.max(0) as u64)).ok().flatten();
    match data {
        Some(mut d) => {
            let r = env.byte_array_from_slice(&d).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut());
            qscrypt_core::util::wipe(&mut d);
            r
        }
        None => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_exportFile<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
    path: JString<'local>,
    out_fd: jint,
    progress: JObject<'local>,
) -> jstring {
    let path = get_string(&mut env, &path);
    let json = {
        let mut p = JProgress::new(&mut env, &progress);
        guarded(|| api::export_file(handle, &path, out_fd, &mut |d, t| p.report(d, t)))
    };
    to_jstring(&mut env, &json)
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_com_qscrypt_app_QsCore_importFile<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
    in_fd: jint,
    size: jlong,
    dest: JString<'local>,
    overwrite: jboolean,
    progress: JObject<'local>,
) -> jstring {
    let dest = get_string(&mut env, &dest);
    let json = {
        let mut p = JProgress::new(&mut env, &progress);
        guarded(|| api::import_file(handle, in_fd, size.max(0) as u64, &dest, overwrite != 0, &mut |d, t| p.report(d, t)))
    };
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_mkdir<'local>(mut env: JNIEnv<'local>, _this: JObject<'local>, handle: jlong, path: JString<'local>) -> jstring {
    let path = get_string(&mut env, &path);
    let json = guarded(|| api::mkdir(handle, &path));
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_remove<'local>(mut env: JNIEnv<'local>, _this: JObject<'local>, handle: jlong, path: JString<'local>) -> jstring {
    let path = get_string(&mut env, &path);
    let json = guarded(|| api::remove(handle, &path));
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_rename<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    handle: jlong,
    path: JString<'local>,
    new_name: JString<'local>,
) -> jstring {
    let path = get_string(&mut env, &path);
    let new_name = get_string(&mut env, &new_name);
    let json = guarded(|| api::rename(handle, &path, &new_name));
    to_jstring(&mut env, &json)
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_com_qscrypt_app_QsCore_createVolume<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    fd: jint,
    size: jlong,
    password: JByteArray<'local>,
    pim: jint,
    prf: jint,
    ea: jint,
    format: jint,
    label: JString<'local>,
    progress: JObject<'local>,
) -> jstring {
    let pw = get_bytes(&mut env, &password);
    let label = get_string(&mut env, &label);
    let json = {
        let mut p = JProgress::new(&mut env, &progress);
        guarded(|| api::create_volume(fd, size.max(0) as u64, &pw, pim.max(0) as u32, prf.max(0) as u32, ea.max(0) as u32, format, &label, &mut |d, t| p.report(d, t)))
    };
    to_jstring(&mut env, &json)
}

#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "system" fn Java_com_qscrypt_app_QsCore_qscEncrypt<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    in_fd: jint,
    size: jlong,
    out_fd: jint,
    name: JString<'local>,
    modified: jlong,
    password: JByteArray<'local>,
    progress: JObject<'local>,
) -> jstring {
    let pw = get_bytes(&mut env, &password);
    let name = get_string(&mut env, &name);
    let json = {
        let mut p = JProgress::new(&mut env, &progress);
        guarded(|| api::qsc_encrypt(in_fd, size.max(0) as u64, out_fd, &name, modified, &pw, &mut |d, t| p.report(d, t)))
    };
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_qscDecrypt<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    in_fd: jint,
    out_fd: jint,
    password: JByteArray<'local>,
    progress: JObject<'local>,
) -> jstring {
    let pw = get_bytes(&mut env, &password);
    let json = {
        let mut p = JProgress::new(&mut env, &progress);
        guarded(|| api::qsc_decrypt(in_fd, out_fd, &pw, &mut |d, t| p.report(d, t)))
    };
    to_jstring(&mut env, &json)
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_pinHash<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    pin: JByteArray<'local>,
    salt: JByteArray<'local>,
) -> jbyteArray {
    let pin = get_bytes(&mut env, &pin);
    let salt = get_bytes(&mut env, &salt);
    match catch_unwind(AssertUnwindSafe(|| api::pin_hash(&pin, &salt))) {
        Ok(Some(h)) => env.byte_array_from_slice(&h).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_openAsset<'local>(
    mut env: JNIEnv<'local>,
    _this: JObject<'local>,
    data: JByteArray<'local>,
    password: JByteArray<'local>,
) -> jbyteArray {
    let blob = env.convert_byte_array(&data).unwrap_or_default();
    let pw = get_bytes(&mut env, &password);
    match catch_unwind(AssertUnwindSafe(|| api::open_asset(&blob, &pw))) {
        Ok(Some(mut plain)) => {
            let r = env.byte_array_from_slice(&plain).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut());
            qscrypt_core::util::wipe(&mut plain);
            r
        }
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_randomBytes<'local>(mut env: JNIEnv<'local>, _this: JObject<'local>, n: jint) -> jbyteArray {
    match catch_unwind(|| api::random_bytes(n.clamp(0, 1 << 20) as usize)) {
        Ok(Some(b)) => env.byte_array_from_slice(&b).map(|a| a.into_raw()).unwrap_or(std::ptr::null_mut()),
        _ => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qscrypt_app_QsCore_sniff<'local>(mut env: JNIEnv<'local>, _this: JObject<'local>, fd: jint) -> jstring {
    let json = guarded(|| api::sniff(fd));
    to_jstring(&mut env, &json)
}
