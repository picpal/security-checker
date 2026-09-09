// kts 회귀 픽스처 — Groovy 명명인자 파서를 kts 에 돌리면 오탐이 나는 관용구를 모아둔다.
// 여기서 dynamic_versions() 는 항상 0건이어야 한다(FP0 게이트).
plugins {
    java
}

repositories { mavenCentral() }

// 콜론이 타입 주석인 자리 — Groovy 였다면 명명인자로 오인된다
fun dep(group: String, name: String, version: String): String = "$group:$name:$version"

fun libraryOf(group: String, name: String): String = "$group:$name"

data class Coord(val group: String, val name: String, val version: String)

dependencies {
    implementation("org.apache.commons:commons-text:1.12.0")
    implementation("com.google.guava:guava:${libs.versions.guava.get()}")
    // kotlin DSL 명명인자(`=`)는 DSL 프로퍼티 대입과 문법이 같아 미대응 — 고정 버전이라 무해
    implementation(group = "org.xerial", name = "sqlite-jdbc", version = "3.46.0.0")
}

tasks.register<Copy>("bundle") {
    from(layout.buildDirectory.dir("libs"))
    into(layout.buildDirectory.dir("dist"))
}
