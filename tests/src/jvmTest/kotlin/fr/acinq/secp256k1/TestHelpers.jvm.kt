package fr.acinq.secp256k1

import kotlinx.serialization.json.JsonElement

actual fun readResourceAsJson(filename: String): JsonElement = readResourceAsJsonDefault(filename)

actual fun readEnvironmentVariable(name: String): String? {
    return System.getenv(name)
}