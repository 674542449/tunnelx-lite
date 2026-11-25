# Keep native JNI entrypoints intact
-keep class com.txlite.android.core.CoreBridge { *; }
-keep class hev.htproxy.TProxyService { *; }

# Keep Android entrypoints & services
-keep class com.txlite.android.TxliteApp { *; }
-keep class com.txlite.android.ui.MainActivity { *; }
-keep class com.txlite.android.vpn.TxliteVpnService { *; }
-keep class com.txlite.android.vpn.TxliteTileService { *; }

# Keep ZXing offline QR scanner activities & camera widgets
-keep class com.journeyapps.barcodescanner.** { *; }
-keep class com.google.zxing.** { *; }
-dontwarn com.google.zxing.**
