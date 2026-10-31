// Runs the generated UniFFI Kotlin bindings against the real cdylib on a JVM.
// scripts/kotlin-test.sh builds the library (feature vector-tests), generates the bindings into
// build/generated and runs this project's tests.
plugins {
    kotlin("jvm") version "2.1.0"
}

repositories { mavenCentral() }

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0")
    testImplementation(kotlin("test"))
    testImplementation("org.json:json:20240303")
}

sourceSets { test { kotlin.srcDir("build/generated/bindings") } }

kotlin { jvmToolchain(21) }

tasks.test {
    useJUnit()
    val lib = System.getenv("SIROS_VERIFIER_CORE_FFI_LIB_DIR") ?: "${rootDir}/../../target/debug"
    systemProperty("jna.library.path", lib)
    testLogging { events("passed", "failed", "skipped"); showStandardStreams = true }
}
