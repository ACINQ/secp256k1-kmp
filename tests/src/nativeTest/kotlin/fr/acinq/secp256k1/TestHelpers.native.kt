package fr.acinq.secp256k1

import platform.posix.*
import kotlinx.cinterop.*
import kotlinx.serialization.json.JsonElement

actual fun readResourceAsJson(filename: String): JsonElement = readResourceAsJsonDefault(filename)

@OptIn(ExperimentalForeignApi::class)
actual fun readEnvironmentVariable(name: String): String? {
    return getenv(name)?.toKString()
}