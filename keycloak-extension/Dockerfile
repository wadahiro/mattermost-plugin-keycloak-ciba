FROM maven:3.8.2-jdk-11 as builder

WORKDIR /build
COPY ./pom.xml /build/
RUN mvn -B package; echo ""

COPY ./src/ /build/src/
RUN mvn -B package

FROM quay.io/keycloak/keycloak:15.0.2

COPY custom-scripts/ /opt/jboss/startup-scripts/
COPY --from=builder /build/target/*.jar /opt/jboss/keycloak/standalone/deployments/
