/*
 * Copyright 2022 RethinkDNS and its authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.celzero.bravedns.backup

import Logger
import Logger.LOG_TAG_BACKUP_RESTORE
import android.content.Context
import android.content.pm.PackageInfo
import android.net.Uri
import androidx.core.net.toUri
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.celzero.bravedns.backup.BackupHelper.Companion.BACKUP_TYPE_FIREWALL_ONLY
import com.celzero.bravedns.backup.BackupHelper.Companion.BACKUP_TYPE_KEY
import com.celzero.bravedns.backup.BackupHelper.Companion.DATA_BUILDER_RESTORE_URI
import com.celzero.bravedns.backup.BackupHelper.Companion.FIREWALL_APP_RULES_FILE_NAME
import com.celzero.bravedns.backup.BackupHelper.Companion.FIREWALL_DOMAIN_RULES_FILE_NAME
import com.celzero.bravedns.backup.BackupHelper.Companion.FIREWALL_IP_RULES_FILE_NAME
import com.celzero.bravedns.backup.BackupHelper.Companion.METADATA_FILENAME
import com.celzero.bravedns.backup.BackupHelper.Companion.VERSION
import com.celzero.bravedns.backup.BackupHelper.Companion.deleteResidue
import com.celzero.bravedns.backup.BackupHelper.Companion.getTempDir
import com.celzero.bravedns.backup.BackupHelper.Companion.stopVpn
import com.celzero.bravedns.backup.BackupHelper.Companion.unzip
import com.celzero.bravedns.database.AppDatabase
import com.celzero.bravedns.database.CustomDomain
import com.celzero.bravedns.database.CustomIp
import com.celzero.bravedns.service.PersistentState
import com.celzero.bravedns.util.Utilities
import com.celzero.bravedns.util.Utilities.deleteRecursive
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import java.io.File
import java.io.IOException
import java.io.InputStream

// Restore scope: firewall rules only (CustomIp, CustomDomain, AppInfo firewall columns).
// Old-format backups that contain SharedPreferences or full databases are refused so that
// no DNS/WireGuard/proxy configuration from another device is silently applied.
class RestoreAgent(val context: Context, workerParams: WorkerParameters) :
    CoroutineWorker(context, workerParams), KoinComponent {

    private val appDatabase by inject<AppDatabase>()
    private val persistentState by inject<PersistentState>()

    companion object {
        const val TAG = "RestoreAgent"
    }

    override suspend fun doWork(): Result {
        val restoreUri = inputData.getString(DATA_BUILDER_RESTORE_URI)?.toUri()
        if (restoreUri == null) {
            Logger.w(LOG_TAG_BACKUP_RESTORE, "restore uri is null, return failure")
            return Result.failure()
        }

        Logger.d(LOG_TAG_BACKUP_RESTORE, "begin restore process with file uri: $restoreUri")
        val result = startRestore(restoreUri)

        Logger.i(LOG_TAG_BACKUP_RESTORE, "completed restore process, is successful? $result")
        return if (result) Result.success() else Result.failure()
    }

    // -------------------------------------------------------------------------
    // Orchestration
    // -------------------------------------------------------------------------

    private suspend fun startRestore(importUri: Uri): Boolean {
        var inputStream: InputStream? = null
        stopVpn(context)
        return try {
            val tempDir = getTempDir(context)
            inputStream = context.contentResolver.openInputStream(importUri)

            Logger.d(LOG_TAG_BACKUP_RESTORE, "restore process, temp dir: ${tempDir.path}")
            if (!unzip(inputStream, tempDir.path)) {
                Logger.w(LOG_TAG_BACKUP_RESTORE, "failed to unzip $importUri → ${tempDir.path}")
                return false
            }

            if (!validateMetadata(tempDir)) {
                Logger.w(LOG_TAG_BACKUP_RESTORE, "metadata validation failed — unsupported or corrupted backup")
                return false
            }

            if (!isFirewallOnlyBackup(tempDir)) {
                // Old-format backups (SharedPreferences + full DB) could silently overwrite
                // DNS/WireGuard/proxy config.  Refuse them rather than apply partial data.
                Logger.w(
                    LOG_TAG_BACKUP_RESTORE,
                    "old-format backup detected (no firewall JSON files). " +
                        "Export a new firewall-only backup from this build and retry."
                )
                return false
            }

            val result = withContext(Dispatchers.IO) {
                restoreFirewallOnly(tempDir)
            }

            updateLatestVersion()
            deleteRecursive(tempDir)
            result
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "exception during restore: ${e.message}", e)
            false
        } finally {
            try { inputStream?.close() } catch (_: IOException) {}
        }
    }

    // -------------------------------------------------------------------------
    // Format detection
    // -------------------------------------------------------------------------

    /** Returns true when the unzipped archive contains the firewall-only JSON files. */
    private fun isFirewallOnlyBackup(tempDir: File): Boolean =
        File(tempDir, FIREWALL_IP_RULES_FILE_NAME).exists() &&
            File(tempDir, FIREWALL_DOMAIN_RULES_FILE_NAME).exists()

    // -------------------------------------------------------------------------
    // Firewall-only restore (SRP: one method per rule domain)
    // -------------------------------------------------------------------------

    private fun restoreFirewallOnly(tempDir: File): Boolean {
        val ipOk = restoreFirewallIpRules(tempDir)
        val domainOk = restoreFirewallDomainRules(tempDir)
        // App-level rules are best-effort: a mismatch (UID, uninstalled app) is non-fatal.
        restoreAppFirewallRules(tempDir)
        return ipOk && domainOk
    }

    /** Clears all CustomIp rows and re-inserts from the backup JSON. */
    private fun restoreFirewallIpRules(tempDir: File): Boolean {
        val file = File(tempDir, FIREWALL_IP_RULES_FILE_NAME)
        if (!file.exists()) {
            Logger.w(LOG_TAG_BACKUP_RESTORE, "IP rules file not found, skipping")
            return false
        }
        return try {
            val dao = appDatabase.customIpEndpointDao()
            val arr = JSONArray(file.readText(Charsets.UTF_8))

            // Atomically replace: delete all, then insert.
            val existing = dao.getCustomIpRules()
            if (existing.isNotEmpty()) dao.deleteAll(existing)

            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val rule = CustomIp().apply {
                    uid             = obj.optInt("uid", 0)
                    ipAddress       = obj.optString("ipAddress", "")
                    port            = obj.optInt("port", 0)
                    protocol        = obj.optString("protocol", "")
                    isActive        = obj.optBoolean("isActive", true)
                    proxyId         = obj.optString("proxyId", "")
                    proxyCC         = obj.optString("proxyCC", "")
                    status          = obj.optInt("status", 0)
                    wildcard        = obj.optBoolean("wildcard", false)
                    ruleType        = obj.optInt("ruleType", 0)
                    modifiedDateTime = obj.optLong("modifiedDateTime", 0L)
                }
                if (rule.ipAddress.isNotEmpty()) dao.insert(rule)
            }
            Logger.i(LOG_TAG_BACKUP_RESTORE, "IP rules restored: ${arr.length()} entries")
            true
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "error restoring IP rules: ${e.message}", e)
            false
        } finally {
            deleteResidue(file)
        }
    }

    /** Clears all CustomDomain rows and re-inserts from the backup JSON. */
    private fun restoreFirewallDomainRules(tempDir: File): Boolean {
        val file = File(tempDir, FIREWALL_DOMAIN_RULES_FILE_NAME)
        if (!file.exists()) {
            Logger.w(LOG_TAG_BACKUP_RESTORE, "domain rules file not found, skipping")
            return false
        }
        return try {
            val dao = appDatabase.customDomainEndpointDAO()
            val arr = JSONArray(file.readText(Charsets.UTF_8))

            // Atomically replace: delete all, then insert.
            dao.deleteAllRules()

            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val domain = obj.optString("domain", "")
                if (domain.isEmpty()) continue
                val rule = CustomDomain(
                    domain      = domain,
                    uid         = obj.optInt("uid", 0),
                    ips         = obj.optString("ips", ""),
                    type        = obj.optInt("type", 0),
                    status      = obj.optInt("status", 0),
                    proxyId     = obj.optString("proxyId", ""),
                    proxyCC     = obj.optString("proxyCC", ""),
                    modifiedTs  = obj.optLong("modifiedTs", System.currentTimeMillis()),
                    deletedTs   = obj.optLong("deletedTs", System.currentTimeMillis()),
                    version     = obj.optLong("version", CustomDomain.getCurrentVersion()),
                )
                dao.insert(rule)
            }
            Logger.i(LOG_TAG_BACKUP_RESTORE, "domain rules restored: ${arr.length()} entries")
            true
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "error restoring domain rules: ${e.message}", e)
            false
        } finally {
            deleteResidue(file)
        }
    }

    /**
     * Best-effort: for each entry in the backup, locate the matching AppInfo row by
     * packageName and update only its firewall columns.  Rows for apps not installed
     * on this device are silently skipped (non-fatal).
     */
    private fun restoreAppFirewallRules(tempDir: File) {
        val file = File(tempDir, FIREWALL_APP_RULES_FILE_NAME)
        if (!file.exists()) {
            Logger.d(LOG_TAG_BACKUP_RESTORE, "app firewall rules file not present, skip")
            return
        }
        try {
            val dao = appDatabase.appInfoDAO()
            val arr = JSONArray(file.readText(Charsets.UTF_8))
            var updated = 0
            for (i in 0 until arr.length()) {
                val obj = arr.optJSONObject(i) ?: continue
                val packageName = obj.optString("packageName", "")
                if (packageName.isEmpty()) continue

                // Resolve the current UID for this package; skip if uninstalled.
                val uid = try {
                    dao.getAppInfoUidForPackageName(packageName)
                } catch (_: Exception) { 0 }
                if (uid == 0) continue

                // Retrieve the full AppInfo row to preserve non-firewall columns.
                val appInfo = try { dao.isUidPkgExist(uid, packageName) } catch (_: Exception) { null }
                if (appInfo == null) continue

                appInfo.firewallStatus    = obj.optInt("firewallStatus", appInfo.firewallStatus)
                appInfo.connectionStatus  = obj.optInt("connectionStatus", appInfo.connectionStatus)
                appInfo.screenOffAllowed  = obj.optBoolean("screenOffAllowed", appInfo.screenOffAllowed)
                appInfo.backgroundAllowed = obj.optBoolean("backgroundAllowed", appInfo.backgroundAllowed)
                appInfo.isProxyExcluded   = obj.optBoolean("isProxyExcluded", appInfo.isProxyExcluded)
                dao.update(appInfo)
                updated++
            }
            Logger.i(LOG_TAG_BACKUP_RESTORE, "app firewall rules restored: $updated / ${arr.length()} entries")
        } catch (e: Exception) {
            Logger.e(LOG_TAG_BACKUP_RESTORE, "error restoring app firewall rules (non-fatal): ${e.message}", e)
        } finally {
            deleteResidue(file)
        }
    }

    // -------------------------------------------------------------------------
    // Metadata validation
    // -------------------------------------------------------------------------

    /**
     * Validates that the backup was created by a compatible app version and is a
     * firewall-only backup created by this build.
     */
    private fun validateMetadata(tempDir: File): Boolean {
        val file = File(tempDir, METADATA_FILENAME)
        if (!file.exists()) {
            Logger.w(LOG_TAG_BACKUP_RESTORE, "metadata file not found")
            return false
        }
        return try {
            val metadata = file.readText()
            isVersionSupported(metadata) && isFirewallOnlyMetadata(metadata)
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "error reading metadata: ${e.message}", e)
            false
        }
    }

    /** Returns true when the metadata's version field satisfies the minimum supported version. */
    private fun isVersionSupported(metadata: String): Boolean {
        val minVersion = 24
        return try {
            if (!metadata.contains(VERSION)) return false
            val parts = metadata.split("|")
            val versionPart = parts.firstOrNull { it.startsWith("$VERSION:") } ?: return false
            val version = versionPart.split(":").getOrNull(1)?.toIntOrNull() ?: return false
            (version >= minVersion).also { ok ->
                if (!ok) Logger.w(LOG_TAG_BACKUP_RESTORE, "backup version $version < min $minVersion")
            }
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "error parsing version: ${e.message}", e)
            false
        }
    }

    /**
     * Returns true when the metadata declares this is a firewall-only backup.
     * Old backups that do not carry the type tag are rejected to prevent silent
     * DNS/WireGuard config pollution.
     */
    private fun isFirewallOnlyMetadata(metadata: String): Boolean {
        val parts = metadata.split("|")
        val typePart = parts.firstOrNull { it.startsWith("$BACKUP_TYPE_KEY:") }
        return if (typePart != null) {
            val type = typePart.split(":").getOrNull(1) ?: ""
            (type == BACKUP_TYPE_FIREWALL_ONLY).also { ok ->
                if (!ok) Logger.w(LOG_TAG_BACKUP_RESTORE, "unsupported backup type: '$type'")
            }
        } else {
            // No type tag → old-format backup.  Reject.
            Logger.w(LOG_TAG_BACKUP_RESTORE, "no backup type tag found; old-format backup rejected")
            false
        }
    }

    // -------------------------------------------------------------------------
    // Version bookkeeping
    // -------------------------------------------------------------------------

    private fun updateLatestVersion() {
        val latest = getInstalledVersionCode()
        if (latest != 0 && latest != persistentState.appVersion) {
            persistentState.appVersion = latest
            Logger.i(LOG_TAG_BACKUP_RESTORE, "app version updated to $latest")
        }
    }

    @Suppress("DEPRECATION")
    private fun getInstalledVersionCode(): Int {
        val pInfo: PackageInfo? =
            Utilities.getPackageMetadata(context.packageManager, context.packageName)
        return pInfo?.versionCode ?: 0
    }
}
