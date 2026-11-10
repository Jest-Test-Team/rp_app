package com.jesttestteam.rp.rp_console

import android.content.ActivityNotFoundException
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/** VPN helpers for the console: which VPN apps are installed, whether a VPN
 *  is up, and opening a VPN app or its store page. Only the two VPN apps
 *  declared in the manifest's <queries> can be looked up. */
class MainActivity : FlutterActivity() {
    private val vpnApps = setOf("com.tailscale.ipn", "com.wireguard.android")

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "rp/vpn").setMethodCallHandler { call, result ->
            when (call.method) {
                "installedApps" -> result.success(vpnApps.associateWith { installed(it) })
                "vpnActive" -> result.success(vpnActive())
                "openApp" -> {
                    val pkg = call.argument<String>("package")
                    if (pkg == null || pkg !in vpnApps) {
                        result.success(false)
                    } else {
                        val i = packageManager.getLaunchIntentForPackage(pkg)
                        if (i == null) result.success(false) else { startActivity(i); result.success(true) }
                    }
                }
                "openStore" -> {
                    val pkg = call.argument<String>("package")
                    if (pkg == null || pkg !in vpnApps) {
                        result.success(false)
                    } else {
                        try {
                            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=$pkg")))
                        } catch (e: ActivityNotFoundException) {
                            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=$pkg")))
                        }
                        result.success(true)
                    }
                }
                "saveConfig" -> {
                    // A WireGuard config for this phone, saved to Downloads so the
                    // WireGuard app can import it (+ › Import from file). Name is
                    // restricted; the content is the config the app just made.
                    val name = call.argument<String>("name") ?: ""
                    val text = call.argument<String>("text") ?: ""
                    if (!Regex("^[A-Za-z0-9_-]{1,40}\\.conf$").matches(name) || Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                        result.success(null)
                    } else {
                        try {
                            val values = ContentValues().apply {
                                put(MediaStore.Downloads.DISPLAY_NAME, name)
                                put(MediaStore.Downloads.MIME_TYPE, "application/octet-stream")
                            }
                            val uri = contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                            if (uri == null) {
                                result.success(null)
                            } else {
                                contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) }
                                result.success("Download/$name")
                            }
                        } catch (e: Exception) {
                            result.success(null)
                        }
                    }
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun installed(pkg: String): Boolean = try {
        packageManager.getPackageInfo(pkg, 0)
        true
    } catch (e: PackageManager.NameNotFoundException) {
        false
    }

    private fun vpnActive(): Boolean {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        return cm.allNetworks.any { n ->
            cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    }
}
