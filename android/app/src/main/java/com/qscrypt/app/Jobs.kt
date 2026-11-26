package com.qscrypt.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.BatteryManager
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Long operations (copying, importing, exporting, encrypting, filling free
 * space, deep checks) run here, one at a time, in the background. Each can
 * be paused, resumed and cancelled; pausing between steps lets others run.
 * Copies between vaults and filling free space are remembered (without
 * secrets) so they can continue after the app was closed.
 */
object Jobs {
    enum class State { Queued, Running, Paused, Done, Failed, Cancelled }

    class Job(val id: Long, val kind: String, val title: String, val vaults: List<Long>, var spec: JSONObject?) {
        var state by mutableStateOf(State.Queued)
        var done by mutableLongStateOf(0L)
        var total by mutableLongStateOf(0L)
        var detail by mutableStateOf("")
        var result by mutableStateOf("")
        /** Paused by the battery rule rather than by the user. */
        var lowBattery by mutableStateOf(false)
        val pauseFlag = AtomicBoolean(false)
        val cancelFlag = AtomicBoolean(false)
        internal var lastSpeedAt = 0L
        internal var lastSpeedDone = 0L
        var speed by mutableLongStateOf(0L)

        val active: Boolean get() = state == State.Queued || state == State.Running || state == State.Paused
        val fraction: Float? get() = if (total > 0) (done.toFloat() / total).coerceIn(0f, 1f) else null

        fun pause() {
            if (active) pauseFlag.set(true)
        }

        fun resume() {
            pauseFlag.set(false)
        }

        fun cancel() {
            cancelFlag.set(true)
            pauseFlag.set(false)
        }

        /** Stopped because its vault closed or the app locked: a copy stays resumable. */
        var interrupted = false
            private set

        fun interrupt() {
            interrupted = true
            cancel()
        }
    }

    /** What a job's work sees: progress reporting with pause and cancel. */
    class Run(val job: Job, private val context: Context) {
        private var lastBatteryCheck = 0L

        private fun batteryLow(): Boolean {
            if (!Prefs.pauseOnLowBattery) return false
            val now = SystemClock.elapsedRealtime()
            if (now - lastBatteryCheck < 20_000 && !job.lowBattery) return false
            if (now - lastBatteryCheck < 5_000) return job.lowBattery
            lastBatteryCheck = now
            job.lowBattery = Power.low(context, job.lowBattery)
            return job.lowBattery
        }

        private fun noteSpeed() {
            val now = SystemClock.elapsedRealtime()
            if (job.lastSpeedAt == 0L) {
                job.lastSpeedAt = now
                job.lastSpeedDone = job.done
            } else if (now - job.lastSpeedAt >= 2000) {
                job.speed = ((job.done - job.lastSpeedDone).coerceAtLeast(0) * 1000) / (now - job.lastSpeedAt)
                job.lastSpeedAt = now
                job.lastSpeedDone = job.done
            }
        }

        /** Engine progress: blocks while paused (inside one file), false once cancelled. */
        fun progress(base: Long = 0, fixedTotal: Long = -1): Progress = Progress { d, t ->
            job.done = base + d
            job.total = if (fixedTotal >= 0) fixedTotal else t
            noteSpeed()
            Jobs.changed(context)
            while ((job.pauseFlag.get() || batteryLow()) && !job.cancelFlag.get()) {
                if (job.state != State.Paused) {
                    job.state = State.Paused
                    Jobs.changed(context)
                }
                Thread.sleep(250)
            }
            if (job.state == State.Paused) {
                job.state = State.Running
                job.lastSpeedAt = 0L
                Jobs.changed(context)
            }
            !job.cancelFlag.get()
        }

        /** Between steps: while paused, lets other jobs run. False once cancelled. */
        suspend fun checkpoint(): Boolean {
            if (job.cancelFlag.get()) return false
            if (job.pauseFlag.get() || batteryLow()) {
                job.state = State.Paused
                Jobs.changed(context)
                slot.release()
                try {
                    while ((job.pauseFlag.get() || batteryLow()) && !job.cancelFlag.get()) delay(300)
                } finally {
                    slot.acquire()
                }
                if (job.cancelFlag.get()) return false
                job.state = State.Running
                job.lastSpeedAt = 0L
                Jobs.changed(context)
            }
            return true
        }

        fun detail(text: String) {
            job.detail = text
            Jobs.changed(context)
        }
    }

    val list = mutableStateListOf<Job>()
    private val nextId = AtomicLong(1)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val slot = Semaphore(1)
    private var app: Context? = null

    /** Called on the main thread when a job ends: its result for the screen that started it. */
    private val listeners = mutableMapOf<Long, (Job) -> Unit>()

    fun init(context: Context) {
        if (app == null) app = context.applicationContext
    }

    val running: List<Job> get() = list.filter { it.active }

    fun busy(handle: Long): Boolean = list.any { it.active && handle in it.vaults }

    fun cancelFor(handle: Long) = list.filter { it.active && handle in it.vaults }.forEach { it.interrupt() }

    /**
     * Queues `work`. `vaults` are the handles it uses (they stay open while it
     * runs). `spec` describes it for resuming after a restart (no secrets).
     */
    fun start(
        context: Context,
        kind: String,
        title: String,
        vaults: List<Long> = emptyList(),
        spec: JSONObject? = null,
        onEnd: ((Job) -> Unit)? = null,
        work: suspend Run.() -> Reply,
    ): Job {
        init(context)
        runCatching { AppState.askNotifications?.invoke() }
        val job = Job(nextId.getAndIncrement(), kind, title, vaults, spec)
        list.add(job)
        if (onEnd != null) listeners[job.id] = onEnd
        save()
        changed(context)
        scope.launch {
            slot.acquire()
            val r = try {
                if (job.cancelFlag.get()) {
                    Reply("""{"ok":false,"code":"cancelled"}""")
                } else {
                    job.state = State.Running
                    changed(context)
                    Run(job, context.applicationContext).work()
                }
            } catch (e: Throwable) {
                Reply(JSONObject().put("ok", false).put("code", "internal").put("message", e.message ?: e.toString()).toString())
            } finally {
                slot.release()
            }
            job.state = when {
                r.ok -> State.Done
                r.code == "cancelled" || job.cancelFlag.get() -> State.Cancelled
                else -> State.Failed
            }
            if (!r.ok && job.state == State.Failed) job.result = r.error
            if (r.ok && job.result.isEmpty()) job.result = r.json.optString("summary")
            val spec = job.spec
            if (job.state == State.Cancelled && job.interrupted && spec != null) {
                job.result = "توقفت لإغلاق الخزنة؛ يمكن استئنافها لاحقاً."
                withContext(Dispatchers.Main) { pending.add(Pending("j${job.id}-${spec.optString("uid")}", job.kind, job.title, spec)) }
            }
            save()
            changed(context)
            withContext(Dispatchers.Main) {
                listeners.remove(job.id)?.invoke(job)
                AppState.jobEnded(job)
            }
        }
        return job
    }

    /** Removes finished jobs from the list. */
    fun clearFinished() {
        list.removeAll { !it.active }
        save()
    }

    // ---------------------------------------------------------------- resuming after a restart

    /** A job that was running when the app last stopped. */
    data class Pending(val id: String, val kind: String, val title: String, val spec: JSONObject)

    val pending = mutableStateListOf<Pending>()

    fun loadPending() {
        val arr = runCatching { JSONArray(Prefs.pendingJobs) }.getOrElse { JSONArray() }
        pending.clear()
        for (i in 0 until arr.length()) {
            val j = arr.optJSONObject(i) ?: continue
            pending.add(Pending(j.optString("id"), j.optString("kind"), j.optString("title"), j.optJSONObject("spec") ?: continue))
        }
    }

    fun dropPending(p: Pending) {
        pending.remove(p)
        save()
    }

    /** Writes the resumable jobs that have not finished, and pending ones not yet resumed. */
    @Synchronized
    fun save() {
        val arr = JSONArray()
        list.filter { it.active && it.spec != null }.forEach { j ->
            arr.put(JSONObject().put("id", "j${j.id}-${j.spec!!.optString("uid")}").put("kind", j.kind).put("title", j.title).put("spec", j.spec))
        }
        pending.forEach { p -> arr.put(JSONObject().put("id", p.id).put("kind", p.kind).put("title", p.title).put("spec", p.spec)) }
        runCatching { Prefs.pendingJobs = arr.toString() }
    }

    // ---------------------------------------------------------------- notification and service

    private var lastNotify = 0L

    /** Something changed: refresh the notification (at most twice a second). */
    fun changed(context: Context) {
        val now = SystemClock.elapsedRealtime()
        val anyActive = list.any { it.active }
        if (anyActive && now - lastNotify < 500) return
        lastNotify = now
        val c = context.applicationContext
        ContextCompat.getMainExecutor(c).execute { JobService.sync(c) }
    }
}

/** Battery state, read from the sticky broadcast (no permission needed). */
object Power {
    /** Low: under 15% and not charging; once low, stays low until 20% or charging. */
    fun low(context: Context, wasLow: Boolean): Boolean {
        val i = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED)) ?: return false
        val level = i.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = i.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        val status = i.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING || status == BatteryManager.BATTERY_STATUS_FULL
        if (level < 0 || scale <= 0 || charging) return false
        val pct = level * 100 / scale
        return if (wasLow) pct < 20 else pct < 15
    }
}

/**
 * Keeps the app alive while jobs run, with a progress notification (pause,
 * resume, cancel). Not used in disguise mode: a notification would name the
 * app. Also shows "vaults open – lock all" while the app is in the background.
 */
class JobService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_PAUSE -> Jobs.running.forEach { it.pause() }
            ACTION_RESUME -> Jobs.running.forEach { it.resume() }
            ACTION_CANCEL -> Jobs.running.forEach { it.cancel() }
        }
        // startForeground must always follow startForegroundService, even when
        // the jobs have just ended; the service then stops right away.
        val n = progressNotification(this) ?: idleNotification(this)
        runCatching {
            if (Build.VERSION.SDK_INT >= 29) startForeground(ID_JOBS, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            else startForeground(ID_JOBS, n)
        }
        if (Jobs.running.isEmpty() || Prefs.disguised) {
            running = false
            @Suppress("DEPRECATION")
            runCatching { if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else stopForeground(true) }
            stopSelf()
        }
        return START_NOT_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        // Swiped away from recents: the jobs keep going while the service lives.
        super.onTaskRemoved(rootIntent)
    }

    companion object {
        private const val CHANNEL_JOBS = "jobs"
        private const val CHANNEL_VAULTS = "vaults"
        private const val ID_JOBS = 41
        private const val ID_VAULTS = 42
        const val ACTION_PAUSE = "com.qscrypt.app.JOBS_PAUSE"
        const val ACTION_RESUME = "com.qscrypt.app.JOBS_RESUME"
        const val ACTION_CANCEL = "com.qscrypt.app.JOBS_CANCEL"
        const val ACTION_LOCK_ALL = "com.qscrypt.app.LOCK_ALL"
        private var running = false

        private fun channels(context: Context) {
            if (Build.VERSION.SDK_INT < 26) return
            val nm = context.getSystemService(NotificationManager::class.java) ?: return
            nm.createNotificationChannel(NotificationChannel(CHANNEL_JOBS, "العمليات الجارية", NotificationManager.IMPORTANCE_LOW).apply { setShowBadge(false) })
            nm.createNotificationChannel(NotificationChannel(CHANNEL_VAULTS, "الخزنات المفتوحة", NotificationManager.IMPORTANCE_LOW).apply { setShowBadge(false) })
        }

        private fun pending(context: Context, action: String, code: Int): PendingIntent {
            val i = Intent(context, JobService::class.java).setAction(action)
            return PendingIntent.getService(context, code, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        }

        private fun openApp(context: Context): PendingIntent? {
            val i = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: return null
            return PendingIntent.getActivity(context, 0, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        }

        private fun idleNotification(context: Context): android.app.Notification {
            channels(context)
            return NotificationCompat.Builder(context, CHANNEL_JOBS)
                .setSmallIcon(R.drawable.ic_lock)
                .setContentTitle("اكتملت العمليات")
                .setSilent(true)
                .build()
        }

        fun progressNotification(context: Context): android.app.Notification? {
            val active = Jobs.running
            if (active.isEmpty() || Prefs.disguised) return null
            channels(context)
            val current = active.firstOrNull { it.state == Jobs.State.Running } ?: active.first()
            val allPaused = active.all { it.state == Jobs.State.Paused || it.pauseFlag.get() }
            val title = if (active.size == 1) current.title else "${active.size} عمليات: ${current.title}"
            val text = when {
                current.lowBattery -> "متوقفة مؤقتاً: البطارية منخفضة"
                allPaused -> "متوقفة مؤقتاً"
                current.fraction != null -> "${(current.fraction!! * 100).toInt()}% · ${humanSize(current.done)} من ${humanSize(current.total)}"
                else -> current.detail.ifEmpty { "جارٍ العمل…" }
            }
            val b = NotificationCompat.Builder(context, CHANNEL_JOBS)
                .setSmallIcon(R.drawable.ic_lock)
                .setContentTitle(title)
                .setContentText(text)
                .setOnlyAlertOnce(true)
                .setOngoing(true)
                .setSilent(true)
                .setCategory(NotificationCompat.CATEGORY_PROGRESS)
                .setContentIntent(openApp(context))
            val f = current.fraction
            if (f != null && !allPaused) b.setProgress(1000, (f * 1000).toInt(), false) else if (!allPaused) b.setProgress(0, 0, true)
            if (allPaused) b.addAction(0, "استئناف", pending(context, ACTION_RESUME, 1)) else b.addAction(0, "إيقاف مؤقت", pending(context, ACTION_PAUSE, 2))
            b.addAction(0, "إلغاء", pending(context, ACTION_CANCEL, 3))
            return b.build()
        }

        /** Starts, updates or stops the service to match the jobs. */
        fun sync(context: Context) {
            val want = Jobs.running.isNotEmpty() && !Prefs.disguised
            if (want) {
                if (!running) {
                    running = true
                    runCatching { ContextCompat.startForegroundService(context, Intent(context, JobService::class.java)) }.onFailure { running = false }
                } else {
                    val n = progressNotification(context) ?: return
                    if (notificationsAllowed(context)) runCatching { NotificationManagerCompat.from(context).notify(ID_JOBS, n) }
                }
            } else if (running) {
                running = false
                runCatching { context.stopService(Intent(context, JobService::class.java)) }
            }
            vaultsNotice(context)
        }

        fun notificationsAllowed(context: Context): Boolean =
            Build.VERSION.SDK_INT < 33 || ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED

        /** "N vaults are open" with a lock-all action, while the app is in the background. */
        fun vaultsNotice(context: Context) {
            val nm = NotificationManagerCompat.from(context)
            val show = AppState.inBackground && AppState.sessions.isNotEmpty() && Jobs.running.isEmpty() && Prefs.openVaultsNotice && !Prefs.disguised
            if (!show || !notificationsAllowed(context)) {
                runCatching { nm.cancel(ID_VAULTS) }
                return
            }
            channels(context)
            val n = AppState.sessions.size
            val lockAll = PendingIntent.getBroadcast(
                context, 4, Intent(context, LockAllReceiver::class.java).setAction(ACTION_LOCK_ALL),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            val notification = NotificationCompat.Builder(context, CHANNEL_VAULTS)
                .setSmallIcon(R.drawable.ic_unlock)
                .setContentTitle(if (n == 1) "خزنة مفتوحة" else "$n خزنات مفتوحة")
                .setContentText("اضغط «أقفل الكل» لإغلاقها بأمان")
                .setOngoing(true)
                .setSilent(true)
                .setContentIntent(openApp(context))
                .addAction(0, "أقفل الكل", lockAll)
                .build()
            runCatching { nm.notify(ID_VAULTS, notification) }
        }
    }
}

/** "Lock all" from the notification or the quick settings tile. */
class LockAllReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == JobService.ACTION_LOCK_ALL) AppState.lockAll(context, "notification")
    }
}
