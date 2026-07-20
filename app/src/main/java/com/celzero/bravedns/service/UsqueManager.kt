package com.celzero.bravedns.service

import Logger
import android.content.Context
import android.util.Log
import java.io.File
import java.io.StringWriter
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

object UsqueManager {
    const val SOCKS_HOST = "127.0.0.1"
    const val SOCKS_PORT = 40000
    private const val BINARY_NAME = "libusque.so"
    @Volatile private var process: Process? = null
    // Prevents concurrent startSocksProxy calls from killing each other (restart storm).
    private val startLock = kotlinx.coroutines.sync.Mutex()
    @Volatile private var isStarting = false

    // ── Immediate death detection ─────────────────────────────────────────────
    // Registered by BraveVPNService; fired as soon as the child process exits
    // so the VPN service can restart usque instantly instead of waiting up to
    // 20 s for the next watchdog tick.
    @Volatile private var deathCallback: (() -> Unit)? = null

    /** Register (or clear) the callback that is invoked the moment usque dies. */
    fun setDeathCallback(cb: (() -> Unit)?) {
        deathCallback = cb
    }

    // ── debug log file ────────────────────────────────────────────────────────
    private fun dlog(ctx: Context, msg: String) {
        Log.d("WARP_DEBUG", msg)
        try {
            File(ctx.filesDir, "warp_debug.txt").appendText("${System.currentTimeMillis()} $msg\n")
        } catch (_: Exception) {}
    }

    fun getDebugLogFile(ctx: Context): File = File(ctx.filesDir, "warp_debug.txt")

    fun readDebugLog(ctx: Context): String {
        return try {
            val f = File(ctx.filesDir, "warp_debug.txt")
            if (f.exists()) f.readText() else "log file not found"
        } catch (e: Exception) {
            "error reading log: ${e.message}"
        }
    }

    fun clearDebugLog(ctx: Context) {
        try { File(ctx.filesDir, "warp_debug.txt").delete() } catch (_: Exception) {}
    }
    // ─────────────────────────────────────────────────────────────────────────

    private fun getBinary(ctx: Context): File {
        val nativeDir = ctx.applicationInfo.nativeLibraryDir
        val bin = File(nativeDir, BINARY_NAME)
        dlog(ctx, "getBinary: path=${bin.absolutePath} exists=${bin.exists()} canExec=${bin.canExecute()} size=${bin.length()}")
        return bin
    }

    fun isRegistered(ctx: Context): Boolean {
        val f = File(ctx.filesDir, "config.json")
        Log.d("WARP_DEBUG", "isRegistered: path=${f.absolutePath} exists=${f.exists()} size=${f.length()}")
        return f.exists() && f.length() > 0L
    }

    suspend fun registerWithWarp(context: Context): Boolean = withContext(Dispatchers.IO) {
        // NOTE: do NOT call clearDebugLog here — logs must persist across register→start sequence
        dlog(context, "registerWithWarp: >>>ENTRY<<<")
        try {
            val bin = getBinary(context)

            if (!bin.exists()) {
                dlog(context, "BINARY NOT FOUND — put libusque.so in jniLibs/arm64-v8a/")
                return@withContext false
            }
            if (!bin.canExecute()) {
                dlog(context, "BINARY NOT EXECUTABLE — W^X policy?")
                return@withContext false
            }

            val configFile = File(context.filesDir, "config.json")
            if (configFile.exists()) {
                configFile.delete()
                dlog(context, "deleted old config.json")
            }

            // --accept-tos skips the stdin TOS prompt entirely
            val cmd = listOf(bin.absolutePath, "register", "--accept-tos", "-c", configFile.absolutePath)
            dlog(context, "cmd=${cmd.joinToString(" ")}")

            val pb = ProcessBuilder(cmd).redirectErrorStream(false)
            // Go 1.24+ uses vDSO __kernel_getrandom which Android's seccomp filter blocks (SIGSYS/exit 159).
            // Disabling vgetrandom forces the Go runtime to use the getrandom syscall instead.
            pb.environment()["GODEBUG"] = "vgetrandom=off"
            val proc = pb.start()

            // read stdout and stderr concurrently to avoid deadlock
            val stdoutWriter = StringWriter()
            val stderrWriter = StringWriter()

            val stdoutThread = Thread {
                try { stdoutWriter.write(proc.inputStream.bufferedReader().readText()) } catch (_: Exception) {}
            }.also { it.start() }

            val stderrThread = Thread {
                try { stderrWriter.write(proc.errorStream.bufferedReader().readText()) } catch (_: Exception) {}
            }.also { it.start() }

            val exit = proc.waitFor()
            stdoutThread.join(3000)
            stderrThread.join(3000)

            dlog(context, "exit=$exit")
            dlog(context, "stdout=${stdoutWriter}")
            dlog(context, "stderr=${stderrWriter}")
            dlog(context, "configExists=${configFile.exists()} size=${configFile.length()}")

            val ok = exit == 0 && configFile.exists() && configFile.length() > 0L
            dlog(context, "result=$ok")
            ok

        } catch (e: Exception) {
            dlog(context, "EXCEPTION ${e.message}\n${e.stackTraceToString()}")
            Logger.e(Logger.LOG_TAG_PROXY, "registerWithWarp exception", e)
            false
        }
    }

    suspend fun startSocksProxy(ctx: Context): Boolean = withContext(Dispatchers.IO) {
        // NOTE: do NOT clearDebugLog here — we need the prior register logs for debugging
        //
        // Bug-fix: use withLock so the guard is inside the critical section, eliminating the
        // TOCTOU race where two coroutines both see isStarting=false and both acquire the lock
        // sequentially, causing the second to kill the process the first just started.
        startLock.withLock {
            isStarting = true
            try {
                startSocksProxyLocked(ctx)
            } finally {
                isStarting = false
            }
        }
    }

    /**
     * Must only be called while [startLock] is held.
     *
     * Fixes four bugs that caused an infinite restart storm and a phantom "STOPPED" UI state:
     *
     * 1. TOCTOU race — guard is now inside the lock (see [startSocksProxy]).
     * 2. probePort hits the dying old process — we now wait for port release before spawning.
     * 3. Death watcher fires when our own process couldn't bind — watcher is only registered
     *    when proc.isAlive is confirmed true after probePort, not just when the port answers.
     * 4. Orphan-process reattach — if the port is alive but our process reference is gone
     *    (e.g. VPN killed mid-session), we reattach instead of spawning a new (doomed) process.
     */
    private fun startSocksProxyLocked(ctx: Context): Boolean {
        dlog(ctx, "startSocksProxy: >>>ENTRY<<<")

        // ── Fast path: already healthy ─────────────────────────────────────────────────────────
        // If our process is alive AND the port is responding, there is nothing to do.
        // Returning true here prevents the needless kill→respawn cycle that triggered the storm.
        val existingProc = process
        if (existingProc != null && existingProc.isAlive && isPortAlive()) {
            dlog(ctx, "startSocksProxy: already running and healthy — skipping restart")
            portConfirmedAlive = true
            return true
        }

        // ── Stop old process and wait for port release ─────────────────────────────────────────
        // Bug fix 2 & 3: after destroy() the OS process may keep the port bound for tens of ms.
        // Spawning a new process before the port is free causes an immediate bind-failure exit,
        // which the death watcher misreads as an unexpected tunnel death and loops forever.
        if (process != null) {
            stopSocksProxy()
            val released = waitForPortRelease(ctx, SOCKS_PORT, timeoutMs = 2000)
            dlog(ctx, "startSocksProxy: port released=$released after stopSocksProxy")
            // If the port is still held after 2 s the new spawn will also fail to bind.
            // Log it and proceed anyway — at least we tried.
        }

        // ── Orphan reattach ────────────────────────────────────────────────────────────────────
        // The port can be alive with process==null when the VPN was killed mid-session and the
        // usque child process survived (different PID namespace). Spawning a duplicate process
        // would fail to bind. Instead, trust the port probe and reattach in-place; the watchdog
        // will detect real tunnel degradation within 20 s.
        if (isPortAlive()) {
            dlog(ctx, "startSocksProxy: port alive but no process ref — reattaching to orphan usque")
            portConfirmedAlive = true
            return true
        }

        try {
            val bin = getBinary(ctx)
            if (!bin.exists() || !bin.canExecute()) {
                dlog(ctx, "startSocksProxy: binary not ready exists=${bin.exists()} canExec=${bin.canExecute()}")
                return false
            }

            val configFile = File(ctx.filesDir, "config.json")
            dlog(ctx, "startSocksProxy: configExists=${configFile.exists()} size=${configFile.length()}")

            // Apply user-configured SNI override (defaults to "cloudflare.com").
            // Read at process-start time so the user's saved value is used for every restart.
            val sni = try {
                org.koin.java.KoinJavaComponent
                    .get<PersistentState>(PersistentState::class.java)
                    .warpSpoofedSni.trim()
            } catch (t: Throwable) {
                dlog(ctx, "startSocksProxy: SNI lookup failed: ${t.message}")
                ""
            }
            val cmd = mutableListOf(
                bin.absolutePath, "socks",
                "-b", SOCKS_HOST,
                "-p", SOCKS_PORT.toString(),
                "-c", configFile.absolutePath
            )
            if (sni.isNotEmpty()) {
                cmd += listOf("-s", sni)
            }
            dlog(ctx, "startSocksProxy: cmd=${cmd.joinToString(" ")}")

            val pb = ProcessBuilder(cmd).redirectErrorStream(false)
            pb.environment()["GODEBUG"] = "vgetrandom=off"
            val proc = pb.start()
            process = proc

            // Drain stdout and stderr in background threads so the process doesn't block on a
            // full pipe buffer. Capture output for diagnostics if the process exits early.
            val outputWriter = StringWriter()
            val errorWriter = StringWriter()
            val outThread = Thread {
                try { outputWriter.write(proc.inputStream.bufferedReader().readText()) } catch (_: Exception) {}
            }.also { it.isDaemon = true; it.start() }
            val errThread = Thread {
                try { errorWriter.write(proc.errorStream.bufferedReader().readText()) } catch (_: Exception) {}
            }.also { it.isDaemon = true; it.start() }

            // Wait for the port to actually be listening (up to 5s) instead of a blind sleep.
            // This prevents a race on slow devices where 1500ms wasn't enough.
            val portReady = probePort(ctx, SOCKS_PORT, timeoutMs = 5000)
            val procAlive = proc.isAlive
            dlog(ctx, "startSocksProxy: proc.isAlive=$procAlive portReady=$portReady")

            // Bug fix 3: only register the death watcher when our process is *still* alive after
            // probePort returns. If proc died while we were probing (e.g. couldn't bind because
            // the orphan-reattach path above was skipped on a borderline race), treat it as a
            // failure rather than setting portConfirmedAlive and triggering an instant callback.
            if (portReady && procAlive) {
                portConfirmedAlive = true
                // Immediate death detection: daemon thread blocks on waitFor() and fires
                // deathCallback the instant the usque child process exits unexpectedly.
                // This collapses the recovery gap from ≤20 s (watchdog tick) to <1 s.
                val capturedProc = proc
                Thread {
                    try {
                        capturedProc.waitFor()
                        // Only fire if this is still the active process and the port was confirmed
                        // alive (i.e., this is an unexpected death, not an intentional stopSocksProxy).
                        if (process === capturedProc && portConfirmedAlive) {
                            portConfirmedAlive = false
                            Log.w("WARP_DEBUG", "usque process died unexpectedly — firing restart callback")
                            deathCallback?.invoke()
                        }
                    } catch (_: Exception) {}
                }.apply { isDaemon = true; name = "usque-death-watcher" }.start()
            } else {
                portConfirmedAlive = false
                // Process already exited — collect its output before reporting failure.
                outThread.join(2000)
                errThread.join(2000)
                val exit = try { proc.exitValue() } catch (_: Exception) { -1 }
                dlog(ctx, "startSocksProxy: exit=$exit")
                dlog(ctx, "startSocksProxy: stdout=${outputWriter}")
                dlog(ctx, "startSocksProxy: stderr=${errorWriter}")
                process = null
            }

            portReady && procAlive

        } catch (e: Exception) {
            dlog(ctx, "startSocksProxy: EXCEPTION ${e.message}\n${e.stackTraceToString()}")
            Logger.e(Logger.LOG_TAG_PROXY, "startSocksProxy exception", e)
            false
        }
    }

    /** Wait until port [port] stops accepting connections or [timeoutMs] elapses. */
    private fun waitForPortRelease(ctx: Context, port: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (!isPortAlive()) return true
            Thread.sleep(100)
        }
        dlog(ctx, "waitForPortRelease: port $port still bound after ${timeoutMs}ms")
        return false
    }

    /** Poll 127.0.0.1:port until it accepts a connection or [timeoutMs] elapses. */
    private fun probePort(ctx: Context, port: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        var attempt = 0
        while (System.currentTimeMillis() < deadline) {
            attempt++
            try {
                java.net.Socket().use { s ->
                    s.connect(java.net.InetSocketAddress("127.0.0.1", port), 300)
                    dlog(ctx, "probePort: port $port ready after ${attempt} attempts")
                    return true
                }
            } catch (_: Exception) {}
            Thread.sleep(200)
        }
        dlog(ctx, "probePort: port $port NOT ready after ${timeoutMs}ms / ${attempt} attempts")
        return false
    }

    fun stopSocksProxy() {
        Log.d("WARP_DEBUG", "stopSocksProxy: isAlive=${process?.isAlive}")
        portConfirmedAlive = false
        process?.destroy()
        process = null
    }

    @Volatile private var portConfirmedAlive = false

    /**
     * True when usque is known to be alive.
     * Auto-clears the stale portConfirmedAlive flag when the process has exited but the flag
     * was not cleared by a death-watcher yet (e.g., flag set before watcher thread started).
     */
    fun isRunning(): Boolean {
        if (isStarting) return true
        val p = process
        if (p != null && !p.isAlive) {
            // Process died without the death-watcher clearing the flag (e.g., watcher thread
            // lost a race). Clear it now so callers get an accurate false instead of stale true.
            portConfirmedAlive = false
            return false
        }
        return p?.isAlive == true || portConfirmedAlive
    }

    /** Quick check (300ms) whether the SOCKS port is already accepting connections. */
    fun isPortAlive(): Boolean {
        return try {
            android.net.TrafficStats.setThreadStatsTag(android.os.Process.myTid())
            try {
                java.net.Socket().use { s ->
                    s.connect(java.net.InetSocketAddress(SOCKS_HOST, SOCKS_PORT), 300)
                    true
                }
            } finally {
                android.net.TrafficStats.clearThreadStatsTag()
            }
        } catch (_: Exception) { false }
    }

    /**
     * Full SOCKS5 handshake probe — confirms the WARP tunnel is alive end-to-end,
     * not just that the port is open. A zombie process can hold the port open while
     * the underlying QUIC/WARP connection to Cloudflare is dead (e.g. after WiFi→LTE).
     */
    suspend fun probeUsqueLiveness(): Boolean = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        // Sprint 17 fix: a simple SOCKS5 handshake to 127.0.0.1:40000 is loopback-only —
        // it succeeds even when the WARP QUIC tunnel to Cloudflare is completely dead.
        // We must send a real SOCKS5 CONNECT through the proxy to an external IP so that
        // the request actually travels through libusque.so → Cloudflare WARP → internet.
        // 1.1.1.1:80 (Cloudflare DNS-over-HTTP) is ideal: same operator as WARP, always up.
        // REP byte 0x00 = "succeeded" → upstream alive. Anything else or exception → dead.
        try {
            android.net.TrafficStats.setThreadStatsTag(android.os.Process.myTid())
            try { java.net.Socket().use { s ->
                s.soTimeout = 5000
                s.connect(java.net.InetSocketAddress(SOCKS_HOST, SOCKS_PORT), 2000)
                val out = s.getOutputStream()
                val inp = s.getInputStream()

                // SOCKS5 greeting: version=5, nmethods=1, method=0x00 (no auth)
                out.write(byteArrayOf(5, 1, 0))
                val greet = ByteArray(2)
                if (inp.read(greet) != 2 || greet[0] != 5.toByte() || greet[1] == 0xFF.toByte()) {
                    return@withContext false
                }

                // SOCKS5 CONNECT to 1.1.1.1:80
                // VER=5, CMD=CONNECT(1), RSV=0, ATYP=IPv4(1), DST.ADDR=1.1.1.1, DST.PORT=80
                out.write(byteArrayOf(5, 1, 0, 1, 1, 1, 1, 1, 0, 80))
                val rep = ByteArray(10) // minimal reply: VER RSV REP RSV ATYP ADDR(4) PORT(2)
                val n = inp.read(rep)
                // rep[1] == 0x00 means "succeeded" — upstream reached 1.1.1.1
                n >= 2 && rep[0] == 5.toByte() && rep[1] == 0x00.toByte()
            }
        } finally { android.net.TrafficStats.clearThreadStatsTag() }
        } catch (_: Exception) { false }
    }


    /**
     * Called from onResume when usqueEnabled=true but process ref is lost.
     * Sets portConfirmedAlive=true so isRunning() returns true and the UI shows ON.
     * The flag is cleared whenever stopSocksProxy is called or a new startSocksProxy runs.
     */
    fun reattachIfPortAlive(ctx: Context) {
        dlog(ctx, "reattachIfPortAlive: port alive, proxy running — restoring isRunning=true without restart")
        portConfirmedAlive = true
    }
}
