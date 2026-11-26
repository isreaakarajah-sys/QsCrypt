package com.qscrypt.app

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.os.Build
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import org.json.JSONObject

/**
 * USB flash drives and disks through USB OTG. The app talks to the drive
 * itself (USB mass storage, bulk-only, SCSI), so encrypted drives Android
 * cannot read are reachable, without root.
 */
object UsbDrives {
    private const val ACTION_PERMISSION = "com.qscrypt.app.USB_PERMISSION"

    data class Drive(val device: UsbDevice, val iface: UsbInterface, val epIn: UsbEndpoint, val epOut: UsbEndpoint) {
        val key: String get() = device.deviceName
        val title: String
            get() = listOfNotNull(device.manufacturerName?.trim(), device.productName?.trim()).filter { it.isNotEmpty() }.joinToString(" ").ifEmpty { "قرص USB" }
    }

    /** A drive the engine has open. `info` is observable: screens redraw when it changes. */
    class Session(val drive: Drive, val conn: UsbDeviceConnection, val handle: Long, info: JSONObject) {
        var info by mutableStateOf(info)
    }

    val sessions = mutableStateListOf<Session>()
    private var app: Context? = null

    fun init(context: Context) {
        if (app != null) return
        app = context.applicationContext
        val r = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                if (i.action != UsbManager.ACTION_USB_DEVICE_DETACHED) return
                @Suppress("DEPRECATION")
                val d: UsbDevice? = if (Build.VERSION.SDK_INT >= 33) i.getParcelableExtra(UsbManager.EXTRA_DEVICE, UsbDevice::class.java) else i.getParcelableExtra(UsbManager.EXTRA_DEVICE)
                sessions.firstOrNull { it.drive.key == d?.deviceName }?.let { detach(it) }
            }
        }
        ContextCompat.registerReceiver(context.applicationContext, r, IntentFilter(UsbManager.ACTION_USB_DEVICE_DETACHED), ContextCompat.RECEIVER_NOT_EXPORTED)
    }

    private fun manager(context: Context) = context.getSystemService(Context.USB_SERVICE) as UsbManager

    /** Connected mass-storage devices (bulk-only transport, SCSI). */
    fun list(context: Context): List<Drive> = runCatching {
        manager(context).deviceList.values.mapNotNull { dev ->
            (0 until dev.interfaceCount).map { dev.getInterface(it) }.firstOrNull {
                it.interfaceClass == UsbConstants.USB_CLASS_MASS_STORAGE && it.interfaceSubclass == 6 && it.interfaceProtocol == 0x50
            }?.let { intf ->
                val eps = (0 until intf.endpointCount).map { intf.getEndpoint(it) }.filter { it.type == UsbConstants.USB_ENDPOINT_XFER_BULK }
                val inEp = eps.firstOrNull { it.direction == UsbConstants.USB_DIR_IN }
                val outEp = eps.firstOrNull { it.direction == UsbConstants.USB_DIR_OUT }
                if (inEp != null && outEp != null) Drive(dev, intf, inEp, outEp) else null
            }
        }
    }.getOrDefault(emptyList())

    fun hasPermission(context: Context, d: Drive) = runCatching { manager(context).hasPermission(d.device) }.getOrDefault(false)

    /** Shows Android's permission dialog; check `hasPermission` when the app resumes. */
    fun requestPermission(context: Context, d: Drive) {
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
        val pi = PendingIntent.getBroadcast(context, 0, Intent(ACTION_PERMISSION).setPackage(context.packageName), flags)
        AppState.pickerOpen = true
        runCatching { manager(context).requestPermission(d.device, pi) }
    }

    fun session(d: Drive): Session? = sessions.firstOrNull { it.drive.key == d.key }

    /** Opens the drive for the engine. Android's own driver lets go of it. */
    fun open(context: Context, d: Drive, readOnly: Boolean = false): Reply {
        session(d)?.let { return Reply(it.info.toString()) }
        val conn = manager(context).openDevice(d.device) ?: return Reply("""{"ok":false,"code":"io","message":"cannot open the USB device"}""")
        if (!conn.claimInterface(d.iface, true)) {
            conn.close()
            return Reply("""{"ok":false,"code":"io","message":"the USB device is busy"}""")
        }
        val r = Call("usb.open").fd("fd", conn.fileDescriptor).put("epIn", d.epIn.address).put("epOut", d.epOut.address)
            .put("iface", d.iface.id).put("readOnly", readOnly).run()
        if (!r.ok) {
            conn.releaseInterface(d.iface)
            conn.close()
            return r
        }
        sessions.add(Session(d, conn, r.json.optLong("handle"), r.json))
        return r
    }

    /** Reads the drive's partitions and what they hold again (after creating a volume). */
    fun refresh(s: Session): Reply {
        val r = Call("usb.info").put("handle", s.handle).run()
        if (r.ok) s.info = r.json
        return r
    }

    /** Replaces the partition table with one partition over the whole drive (erases the table). */
    fun partition(s: Session, type: Int): Reply {
        val r = Call("usb.partition").put("handle", s.handle).put("type", type).run()
        if (r.ok) s.info = r.json
        return r
    }

    /** A placeholder container for a USB target (vault sessions key on its uri). */
    fun container(s: Session, t: UsbTarget): Container =
        Container("usb:${s.handle}:${t.start}", "${s.drive.title} · ${t.title}", t.size, System.currentTimeMillis())

    /** Closes the drive, and every vault opened on it. */
    fun close(s: Session) {
        AppState.sessions.filter { it.container.uri.startsWith("usb:${s.handle}:") }.forEach { AppState.closeSession(it.handle) }
        Call("usb.close").put("handle", s.handle).run()
        runCatching { s.conn.releaseInterface(s.drive.iface) }
        runCatching { s.conn.close() }
        sessions.remove(s)
    }

    private fun detach(s: Session) = close(s)

    /** The whole drive, or one of its partitions, as an engine source. */
    fun targets(s: Session): List<UsbTarget> {
        val out = mutableListOf<UsbTarget>()
        val parts = s.info.optJSONArray("partitions")
        val size = s.info.optLong("size")
        out.add(UsbTarget(s.handle, 0, size, "القرص كاملاً", s.info.optString("kind")))
        if (parts != null) {
            for (i in 0 until parts.length()) {
                val p = parts.getJSONObject(i)
                out.add(UsbTarget(s.handle, p.optLong("start"), p.optLong("size"), "القسم ${p.optInt("index")}" + p.optString("name").let { if (it.isNotBlank()) " · $it" else "" }, p.optString("kind")))
            }
        }
        return out
    }
}
