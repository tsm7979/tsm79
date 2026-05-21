# ── Stage 1: Build ───────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jdk-jammy AS build

WORKDIR /build

# Copy Maven wrapper + POM first (layer-cache dependencies)
COPY .mvn/              .mvn/
COPY mvnw               mvnw
COPY pom.xml            pom.xml
RUN chmod +x mvnw && ./mvnw dependency:go-offline -q

# Copy source and build fat JAR (skip tests — run in CI separately)
COPY src/ src/
RUN ./mvnw package -DskipTests -q

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM eclipse-temurin:21-jre-jammy AS runtime

# Non-root user
RUN groupadd --system tsm && useradd --system --gid tsm --no-create-home tsm

WORKDIR /app

# Copy JAR from build stage
COPY --from=build /build/target/admin-api-*.jar app.jar

# Expose admin port (mapped in docker-compose to stay on tsm-internal)
EXPOSE 9090

# Healthcheck using the Spring Actuator endpoint
HEALTHCHECK --interval=15s --timeout=10s --start-period=30s --retries=5 \
    CMD wget -qO- http://localhost:9090/actuator/health || exit 1

USER tsm

# JVM flags injected via JAVA_OPTS env (set in docker-compose)
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
