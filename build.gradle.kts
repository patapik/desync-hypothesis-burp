plugins {
    id("java")
}

group = "com.maciejgojny"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.8")

    testImplementation(platform("org.junit:junit-bom:5.11.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
}

tasks.jar {
    archiveBaseName.set("desync-hypothesis-burp")
    archiveVersion.set("")
    manifest {
        attributes("Implementation-Title" to "Desync Hypothesis Scanner")
        attributes("Implementation-Vendor" to "Maciej Gojny")
    }
}
