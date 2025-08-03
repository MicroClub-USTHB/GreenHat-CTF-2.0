# -------- Build stage --------
FROM eclipse-temurin:17-jdk-alpine AS build

WORKDIR /app

COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .
COPY src src

RUN chmod +x ./gradlew

RUN ./gradlew build --no-daemon

# -------- Final stage --------
FROM eclipse-temurin:17-jre-alpine

WORKDIR /app

COPY --from=build /app/build/libs/cold-cash.jar cold-cash.jar

RUN echo "ghctf{j4va_M4ster_Gl1tch3er!!}" > /flag.txt

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "cold-cash.jar"]
