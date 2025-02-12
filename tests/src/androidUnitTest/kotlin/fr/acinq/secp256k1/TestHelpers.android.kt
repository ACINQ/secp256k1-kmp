package fr.acinq.secp256k1

actual fun readEnvironmentVariable(name: String): String? {
    return System.getenv(name)
}