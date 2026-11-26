package com.qscrypt.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build

/**
 * Whether the phone has a network, for the "offline only" policy. Needs only
 * ACCESS_NETWORK_STATE; QsCrypt itself still has no INTERNET permission.
 */
object Net {
    private var app: Context? = null

    fun init(context: Context) {
        app = context.applicationContext
    }

    @Suppress("DEPRECATION")
    fun online(): Boolean {
        val cm = app?.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        return runCatching {
            if (Build.VERSION.SDK_INT >= 23) {
                val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
                // Any transport counts, validated or not: "connected" is what the policy means.
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            } else {
                cm.activeNetworkInfo?.isConnected == true
            }
        }.getOrDefault(true)
    }
}
