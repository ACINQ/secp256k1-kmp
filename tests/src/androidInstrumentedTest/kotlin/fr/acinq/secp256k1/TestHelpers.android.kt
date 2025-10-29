package fr.acinq.secp256k1

import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

val context = InstrumentationRegistry.getInstrumentation().targetContext
val assetManager = context.assets

actual fun readResourceAsJson(filename: String): JsonElement {
    // Open the file from the assets folder
    val inputStream = assetManager.open(filename)
    val raw = inputStream.bufferedReader().use { it.readText() }
    val format = Json { ignoreUnknownKeys = true }
    return format.parseToJsonElement(raw)
}
