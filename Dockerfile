FROM openjdk:15-jdk-slim

WORKDIR /opt/app/

COPY ./target/route53-ssl-monitor-*-jar-with-dependencies.jar /opt/app/jar.jar

ENTRYPOINT exec java $EXTRA_JAVA_OPTS -jar jar.jar