package fr.acinq.secp256k1

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.*

/*--------------------------------------------------------------------------
 *  Copyright 2008 Taro L. Saito
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *--------------------------------------------------------------------------*/ /**
 * Provides OS name and architecture name.
 *
 * @author leo
 */
@Suppress("DuplicatedCode")
internal object OSInfo {
    private val archMapping = HashMap<String, String>()
    private const val X86 = "x86"
    private const val X86_64 = "x86_64"
    private const val IA64_32 = "ia64_32"
    private const val IA64 = "ia64"
    private const val PPC = "ppc"
    private const val PPC64 = "ppc64"

    @JvmStatic val nativeSuffix: String get() = "$os-$arch"

    @JvmStatic val os: String get() = translateOSName(System.getProperty("os.name"))

    @JvmStatic val hardwareName: String get() =
        try {
            val p = Runtime.getRuntime().exec("uname -m")
            p.waitFor()
            val input = p.inputStream
            input.use {
                val b = ByteArrayOutputStream()
                val buf = ByteArray(32)
                var readLen = it.read(buf, 0, buf.size)
                while (readLen >= 0) {
                    b.write(buf, 0, readLen)
                    readLen = it.read(buf, 0, buf.size)
                }
                b.toString()
            }
        } catch (e: Throwable) {
            System.err.println("Error while running uname -m: " + e.message)
            "unknown"
        }

    @JvmStatic
    private fun resolveArmArchType(): String {
        if (System.getProperty("os.name").contains("Linux")) {
            val armType = hardwareName
            // armType (uname -m) can be armv5t, armv5te, armv5tej, armv5tejl, armv6, armv7, armv7l, aarch64, i686// ignored: fall back to "arm" arch (soft-float ABI)
            // ignored: fall back to "arm" arch (soft-float ABI)
            // determine if first JVM found uses ARM hard-float ABI
            when {
                armType.startsWith("armv6") -> {
                    // Raspberry PI
                    return "armv6"
                }
                armType.startsWith("armv7") -> {
                    // Generic
                    return "armv7"
                }
                armType.startsWith("armv5") -> {
                    // Use armv5, soft-float ABI
                    return "arm"
                }
                armType == "aarch64" -> {
                    // Use arm64
                    return "arm64"
                }

                // Java 1.8 introduces a system property to determine armel or armhf
                // http://bugs.java.com/bugdatabase/view_bug.do?bug_id=8005545

                // For java7, we stil need to if run some shell commands to determine ABI of JVM
                else -> {
                    val abi = System.getProperty("sun.arch.abi")
                    if (abi != null && abi.startsWith("gnueabihf")) {
                        return "armv7"
                    }

                    // For java7, we stil need to if run some shell commands to determine ABI of JVM
                    val javaHome = System.getProperty("java.home")
                    try {
                        // determine if first JVM found uses ARM hard-float ABI
                        var exitCode = Runtime.getRuntime().exec("which readelf").waitFor()
                        if (exitCode == 0) {
                            val cmdarray = arrayOf(
                                "/bin/sh", "-c", "find '" + javaHome +
                                        "' -name 'libjvm.so' | head -1 | xargs readelf -A | " +
                                        "grep 'Tag_ABI_VFP_args: VFP registers'"
                            )
                            exitCode = Runtime.getRuntime().exec(cmdarray).waitFor()
                            if (exitCode == 0) {
                                return "armv7"
                            }
                        } else {
                            System.err.println(
                                "WARNING! readelf not found. Cannot check if running on an armhf system, " +
                                        "armel architecture will be presumed."
                            )
                        }
                    } catch (e: IOException) {
                        // ignored: fall back to "arm" arch (soft-float ABI)
                    } catch (e: InterruptedException) {
                        // ignored: fall back to "arm" arch (soft-float ABI)
                    }
                }
            }

            // Java 1.8 introduces a system property to determine armel or armhf
            // http://bugs.java.com/bugdatabase/view_bug.do?bug_id=8005545
            val abi = System.getProperty("sun.arch.abi")
            if (abi != null && abi.startsWith("gnueabihf")) {
                return "armv7"
            }

            // For java7, we stil need to if run some shell commands to determine ABI of JVM
            val javaHome = System.getProperty("java.home")
            try {
                // determine if first JVM found uses ARM hard-float ABI
                var exitCode = Runtime.getRuntime().exec("which readelf").waitFor()
                if (exitCode == 0) {
                    val cmdarray = arrayOf(
                        "/bin/sh", "-c", "find '" + javaHome +
                                "' -name 'libjvm.so' | head -1 | xargs readelf -A | " +
                                "grep 'Tag_ABI_VFP_args: VFP registers'"
                    )
                    exitCode = Runtime.getRuntime().exec(cmdarray).waitFor()
                    if (exitCode == 0) {
                        return "armv7"
                    }
                } else {
                    System.err.println(
                        "WARNING! readelf not found. Cannot check if running on an armhf system, " +
                                "armel architecture will be presumed."
                    )
                }
            } catch (e: IOException) {
                // ignored: fall back to "arm" arch (soft-float ABI)
            } catch (e: InterruptedException) {
                // ignored: fall back to "arm" arch (soft-float ABI)
            }
        }
        // Use armv5, soft-float ABI
        return "arm"
    }

    // For Android
    @JvmStatic
    val arch: String?
        get() {
            val systemOsArch = System.getProperty("os.arch")
            val osArch =
                if (systemOsArch.startsWith("arm")) {
                    resolveArmArchType()
                } else {
                    val lc = systemOsArch.toLowerCase(Locale.US)
                    if (archMapping.containsKey(lc)) return archMapping[lc]
                    systemOsArch
                }
            return translateArchNameToFolderName(osArch)
        }

    @JvmStatic
    fun translateOSName(osName: String): String =
        when {
            osName.contains("Windows") -> "mingw"
            osName.contains("Mac") || osName.contains("Darwin") -> "darwin"
            osName.contains("Linux") -> "linux"
            osName.contains("AIX") -> "aix"
            else -> osName.replace("\\W".toRegex(), "")
        }

    @JvmStatic
    fun translateArchNameToFolderName(archName: String): String = archName.replace("\\W".toRegex(), "")

    init {
        // x86 mappings
        archMapping[X86] = X86
        archMapping["i386"] = X86
        archMapping["i486"] = X86
        archMapping["i586"] = X86
        archMapping["i686"] = X86
        archMapping["pentium"] = X86

        // x86_64 mappings
        archMapping[X86_64] = X86_64
        archMapping["amd64"] = X86_64
        archMapping["em64t"] = X86_64
        archMapping["universal"] = X86_64 // Needed for openjdk7 in Mac

        // Itenium 64-bit mappings
        archMapping[IA64] = IA64
        archMapping["ia64w"] = IA64

        // Itenium 32-bit mappings, usually an HP-UX construct
        archMapping[IA64_32] = IA64_32
        archMapping["ia64n"] = IA64_32

        // PowerPC mappings
        archMapping[PPC] = PPC
        archMapping["power"] = PPC
        archMapping["powerpc"] = PPC
        archMapping["power_pc"] = PPC
        archMapping["power_rs"] = PPC

        // TODO: PowerPC 64bit mappings
        archMapping[PPC64] = PPC64
        archMapping["power64"] = PPC64
        archMapping["powerpc64"] = PPC64
        archMapping["power_pc64"] = PPC64
        archMapping["power_rs64"] = PPC64
    }
}