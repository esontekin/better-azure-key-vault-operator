# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------------------
# Stage 1: Build Angular 21 production bundle (pinned Node 24 LTS Alpine)
# ---------------------------------------------------------------------------
FROM docker.io/library/node:24.21.0-alpine AS frontend-build

WORKDIR /workspace/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
RUN npm run build -- --configuration production

# ---------------------------------------------------------------------------
# Stage 2: Build Spring Boot 3.5 executable JAR (pinned Temurin JDK 21 Alpine)
# ---------------------------------------------------------------------------
FROM docker.io/library/eclipse-temurin:21.0.5_11-jdk-alpine AS backend-build

WORKDIR /workspace

COPY gradlew settings.gradle build.gradle ./
COPY gradle ./gradle
COPY backend ./backend
COPY --from=frontend-build /workspace/frontend/dist/akv-manager/browser ./backend/src/main/resources/static

RUN sed -i 's/\r$//' ./gradlew \
    && chmod +x ./gradlew \
    && ./gradlew :backend:bootJar -PskipFrontendBuild=true --no-daemon

# ---------------------------------------------------------------------------
# Stage 3: Minimal non-root, read-only-root-fs compatible runtime
# ---------------------------------------------------------------------------
FROM docker.io/library/eclipse-temurin:21.0.5_11-jre-alpine AS runtime

RUN addgroup -g 10001 -S akvuser \
    && adduser -u 10001 -S -G akvuser -h /app -s /sbin/nologin akvuser

WORKDIR /app

COPY --from=backend-build --chown=10001:10001 /workspace/backend/build/libs/azure-key-vault-operator.jar /app/app.jar

ENV APP_PROFILE="local" \
    SERVER_ADDRESS="127.0.0.1" \
    SERVER_PORT="8765" \
    SERVER_TOMCAT_BASEDIR="/tmp/tomcat" \
    JAVA_OPTS="-XX:MaxRAMPercentage=75.0 -Djava.io.tmpdir=/tmp"

USER 10001:10001

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${SERVER_PORT:-8765}/actuator/health" || exit 1

ENTRYPOINT ["sh", "-c", "exec java ${JAVA_OPTS} -Dserver.tomcat.basedir=${SERVER_TOMCAT_BASEDIR:-/tmp/tomcat} -jar /app/app.jar"]
