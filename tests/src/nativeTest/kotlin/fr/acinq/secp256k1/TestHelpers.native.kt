package fr.acinq.secp256k1

import platform.posix.*
import kotlinx.cinterop.*

@OptIn(ExperimentalForeignApi::class)
actual fun readEnvironmentVariable(name: String): String? {
    return getenv(name)?.toKString()
}