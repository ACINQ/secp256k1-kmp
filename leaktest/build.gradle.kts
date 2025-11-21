plugins {
    kotlin("jvm")
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(rootProject)
    implementation(project(":jni:jvm:all"))
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(21)
}

application {
    applicationDefaultJvmArgs = listOf("-XX:NativeMemoryTracking=detail")
    mainClass = "fr.acinq.secp256k1.MainKt"
}

tasks.named<CreateStartScripts>("startScripts") {
    doLast {
        // Customizing the Unix start script
        val unixScriptText = unixScript.readText()

        // Append custom JVM args to the generated script
        val updatedUnixScript = unixScriptText.replace(
            "exec ",
            "exec valgrind --leak-check=full --track-origins=yes "
        )

        // Write the modified script back to the file
        unixScript.writeText(updatedUnixScript)
    }
}