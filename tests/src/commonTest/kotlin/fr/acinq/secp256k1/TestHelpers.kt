package fr.acinq.secp256k1

import kotlinx.io.buffered
import kotlinx.io.files.Path
import kotlinx.io.files.SystemFileSystem
import kotlinx.io.readString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

expect fun readResourceAsJson(filename: String): JsonElement

fun readResourceAsJsonDefault(filename: String): JsonElement {
    val resourcesPath = "src/commonTest/resources"
    val raw = SystemFileSystem.source(Path(resourcesPath, filename)).buffered().readString()
    val format = Json { ignoreUnknownKeys = true }
    return format.parseToJsonElement(raw)
}
