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
import android.net.Uri
import android.os.SystemClock
import androidx.core.net.toUri
import androidx.work.Worker
import androidx.work.WorkerParameters
import com.celzero.bravedns.backup.BackupHelper.Companion.BACKUP_TYPE_FIREWALL_ONLY
import com.celzero.bravedns.backup.BackupHelper.Companion.BACKUP_TYPE_KEY
import com.celzero.bravedns.backup.BackupHelper.Companion.CREATED_TIME
import com.celzero.bravedns.backup.BackupHelper.Companion.DATA_BUILDER_BACKUP_URI
import com.celzero.bravedns.backup.BackupHelper.Companion.FIREWALL_APP_RULES_FILE_NAME
import com.celzero.bravedns.backup.BackupHelper.Companion.FIREWALL_DOMAIN_RULES_FILE_NAME
import com.celzero.bravedns.backup.BackupHelper.Companion.FIREWALL_IP_RULES_FILE_NAME
import com.celzero.bravedns.backup.BackupHelper.Companion.METADATA_FILENAME
import com.celzero.bravedns.backup.BackupHelper.Companion.PACKAGE_NAME
import com.celzero.bravedns.backup.BackupHelper.Companion.TEMP_ZIP_FILE_NAME
import com.celzero.bravedns.backup.BackupHelper.Companion.VERSION
import com.celzero.bravedns.backup.BackupHelper.Companion.deleteResidue
import com.celzero.bravedns.backup.BackupHelper.Companion.getFileNameFromPath
import com.celzero.bravedns.backup.BackupHelper.Companion.startVpn
import com.celzero.bravedns.database.AppDatabase
import com.celzero.bravedns.service.PersistentState
import com.celzero.bravedns.util.Utilities.copyWithStream
import org.json.JSONArray
import org.json.JSONObject
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

// Backup scope: firewall rules only (CustomIp, CustomDomain, AppInfo firewall columns).
// DNS settings, WireGuard configs, and SharedPreferences are intentionally excluded so
// that a restored backup does not corrupt DNS or proxy configuration on the target device.
class BackupAgent(val context: Context, workerParams: WorkerParameters) :
    Worker(context, workerParams), KoinComponent {

    private val filesPathToZip: MutableList<String> = ArrayList()
    private val persistentState by inject<PersistentState>()
    private val appDatabase by inject<AppDatabase>()

    companion object {
        const val TAG = "BackupExport"
    }

    override fun doWork(): Result {
        val backupFileUri = inputData.getString(DATA_BUILDER_BACKUP_URI)?.toUri()
        if (backupFileUri == null) {
            Logger.w(LOG_TAG_BACKUP_RESTORE, "backup file uri is null, return failure")
            return Result.failure()
        }

        Logger.d(LOG_TAG_BACKUP_RESTORE, "begin backup process with file uri: $backupFileUri")
        val isBackupSucceed = startBackupProcess(backupFileUri)

        Logger.i(
            LOG_TAG_BACKUP_RESTORE,
            "completed backup process, is backup successful? $isBackupSucceed"
        )
        return if (isBackupSucceed) {
            startVpn(context)
            Result.success()
        } else {
            Result.failure()
        }
    }

    // -------------------------------------------------------------------------
    // Orchestration
    // -------------------------------------------------------------------------

    private fun startBackupProcess(backupFileUri: Uri): Boolean {
        try {
            val tempDir = BackupHelper.getTempDir(context)
            Logger.d(LOG_TAG_BACKUP_RESTORE, "backup process, temp dir: ${tempDir.path}")

            if (!saveFirewallIpRulesToFile(tempDir)) {
                Logger.w(LOG_TAG_BACKUP_RESTORE, "failed to backup IP rules, return failure")
                return false
            }
            if (!saveFirewallDomainRulesToFile(tempDir)) {
                Logger.w(LOG_TAG_BACKUP_RESTORE, "failed to backup domain rules, return failure")
                return false
            }
            // App-level firewall rules are best-effort — a failure does not abort the backup.
            if (!saveAppFirewallRulesToFile(tempDir)) {
                Logger.w(LOG_TAG_BACKUP_RESTORE, "failed to backup app firewall rules (non-fatal), continuing")
            }
            if (!createMetaData(tempDir)) {
                Logger.w(LOG_TAG_BACKUP_RESTORE, "failed to create metadata, return failure")
                return false
            }
            return zipAndCopyToDestination(tempDir, backupFileUri)
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "exception during backup: ${e.message}", e)
            return false
        } finally {
            filesPathToZip.forEach { deleteResidue(File(it)) }
            filesPathToZip.clear()
        }
    }

    // -------------------------------------------------------------------------
    // Firewall rule export (SRP: one method per rule domain)
    // -------------------------------------------------------------------------

    /** Exports all CustomIp rows to [FIREWALL_IP_RULES_FILE_NAME] in [tempDir]. */
    private fun saveFirewallIpRulesToFile(tempDir: File): Boolean {
        val file = File(tempDir, FIREWALL_IP_RULES_FILE_NAME)
        return try {
            val rules = appDatabase.customIpEndpointDao().getCustomIpRules()
            val arr = JSONArray()
            for (rule in rules) {
                arr.put(JSONObject().apply {
                    put("uid", rule.uid)
                    put("ipAddress", rule.ipAddress)
                    put("port", rule.port)
                    put("protocol", rule.protocol)
                    put("isActive", rule.isActive)
                    put("proxyId", rule.proxyId)
                    put("proxyCC", rule.proxyCC)
                    put("status", rule.status)
                    put("wildcard", rule.wildcard)
                    put("ruleType", rule.ruleType)
                    put("modifiedDateTime", rule.modifiedDateTime)
                })
            }
            file.writeText(arr.toString(), Charsets.UTF_8)
            filesPathToZip.add(file.absolutePath)
            Logger.i(LOG_TAG_BACKUP_RESTORE, "IP rules backed up: ${rules.size} entries")
            true
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "error backing up IP rules: ${e.message}", e)
            false
        }
    }

    /** Exports all CustomDomain rows to [FIREWALL_DOMAIN_RULES_FILE_NAME] in [tempDir]. */
    private fun saveFirewallDomainRulesToFile(tempDir: File): Boolean {
        val file = File(tempDir, FIREWALL_DOMAIN_RULES_FILE_NAME)
        return try {
            val rules = appDatabase.customDomainEndpointDAO().getAllDomains()
            val arr = JSONArray()
            for (rule in rules) {
                arr.put(JSONObject().apply {
                    put("domain", rule.domain)
                    put("uid", rule.uid)
                    put("ips", rule.ips)
                    put("status", rule.status)
                    put("type", rule.type)
                    put("proxyId", rule.proxyId)
                    put("proxyCC", rule.proxyCC)
                    put("modifiedTs", rule.modifiedTs)
                    put("deletedTs", rule.deletedTs)
                    put("version", rule.version)
                })
            }
            file.writeText(arr.toString(), Charsets.UTF_8)
            filesPathToZip.add(file.absolutePath)
            Logger.i(LOG_TAG_BACKUP_RESTORE, "domain rules backed up: ${rules.size} entries")
            true
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "error backing up domain rules: ${e.message}", e)
            false
        }
    }

    /**
     * Exports per-app firewall columns (packageName, uid, firewallStatus, connectionStatus,
     * screenOffAllowed, backgroundAllowed, isProxyExcluded) to [FIREWALL_APP_RULES_FILE_NAME].
     * Usage stats (wifiDataUsed, mobileDataUsed, …) are not included.
     */
    private fun saveAppFirewallRulesToFile(tempDir: File): Boolean {
        val file = File(tempDir, FIREWALL_APP_RULES_FILE_NAME)
        return try {
            val apps = appDatabase.appInfoDAO().getAllAppDetails()
            val arr = JSONArray()
            for (app in apps) {
                arr.put(JSONObject().apply {
                    put("packageName", app.packageName)
                    put("uid", app.uid)
                    put("firewallStatus", app.firewallStatus)
                    put("connectionStatus", app.connectionStatus)
                    put("screenOffAllowed", app.screenOffAllowed)
                    put("backgroundAllowed", app.backgroundAllowed)
                    put("isProxyExcluded", app.isProxyExcluded)
                })
            }
            file.writeText(arr.toString(), Charsets.UTF_8)
            filesPathToZip.add(file.absolutePath)
            Logger.i(LOG_TAG_BACKUP_RESTORE, "app firewall rules backed up: ${apps.size} entries")
            true
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "error backing up app firewall rules: ${e.message}", e)
            false
        }
    }

    // -------------------------------------------------------------------------
    // Metadata
    // -------------------------------------------------------------------------

    private fun createMetaData(backupDir: File): Boolean {
        Logger.d(LOG_TAG_BACKUP_RESTORE, "creating meta data file, path: ${backupDir.path}")
        val file = File(backupDir, METADATA_FILENAME)
        if (file.exists()) {
            Logger.d(LOG_TAG_BACKUP_RESTORE, "metadata file exists, deleting it")
            file.delete()
            filesPathToZip.remove(file.absolutePath)
        }
        return try {
            file.writer().use { it.write(backupMetadata()); it.flush() }
            filesPathToZip.add(file.absolutePath)
            true
        } catch (e: Exception) {
            Logger.crash(LOG_TAG_BACKUP_RESTORE, "exception while creating meta data: ${e.message}", e)
            false
        }
    }

    private fun backupMetadata(): String {
        return "$VERSION:${persistentState.appVersion}" +
            "|$PACKAGE_NAME:${context.packageName}" +
            "|$CREATED_TIME:${SystemClock.elapsedRealtime()}" +
            "|$BACKUP_TYPE_KEY:$BACKUP_TYPE_FIREWALL_ONLY"
    }

    // -------------------------------------------------------------------------
    // Zip + copy to destination URI
    // -------------------------------------------------------------------------

    private fun zipAndCopyToDestination(tempDir: File, destUri: Uri): Boolean {
        val bZipSucceeded = zip(filesPathToZip, tempDir.path)
        Logger.i(LOG_TAG_BACKUP_RESTORE, "backup zip completed, success=$bZipSucceeded, dest=$destUri")
        if (!bZipSucceeded) {
            Logger.w(LOG_TAG_BACKUP_RESTORE, "backup zip failed, do not proceed")
            return false
        }
        val tempZipFile = File(tempDir, TEMP_ZIP_FILE_NAME)
        val zipFileUri: Uri = Uri.fromFile(tempZipFile)
        val inputStream: InputStream =
            context.contentResolver.openInputStream(zipFileUri) ?: return false
        val outputStream: OutputStream =
            context.contentResolver.openOutputStream(destUri) ?: run {
                inputStream.close()
                return false
            }
        val copySucceeded = copyWithStream(inputStream, outputStream)
        return if (copySucceeded) {
            Logger.i(LOG_TAG_BACKUP_RESTORE, "copy completed, delete temp zip ${tempZipFile.path}")
            deleteResidue(tempZipFile)
            true
        } else {
            Logger.w(LOG_TAG_BACKUP_RESTORE, "copy failed to destination: ${zipFileUri.path}")
            false
        }
    }

    private fun zip(files: List<String>, zipDirectory: String): Boolean {
        val outputFileName = zipDirectory + File.separator + TEMP_ZIP_FILE_NAME
        Logger.d(LOG_TAG_BACKUP_RESTORE, "zipping files: $files → $outputFileName")
        return try {
            val bufferSize = 80_000
            val data = ByteArray(bufferSize)
            ZipOutputStream(BufferedOutputStream(FileOutputStream(outputFileName))).use { out ->
                for (file in files) {
                    BufferedInputStream(FileInputStream(file), bufferSize).use { origin ->
                        out.putNextEntry(ZipEntry(getFileNameFromPath(file)))
                        var count: Int
                        while (origin.read(data, 0, bufferSize).also { count = it } != -1) {
                            out.write(data, 0, count)
                        }
                    }
                    Logger.d(LOG_TAG_BACKUP_RESTORE, "$file added to zip")
                }
            }
            Logger.i(LOG_TAG_BACKUP_RESTORE, "zip complete: $files")
            true
        } catch (e: Exception) {
            Logger.e(LOG_TAG_BACKUP_RESTORE, "error while zipping: ${e.message}", e)
            false
        }
    }
}
