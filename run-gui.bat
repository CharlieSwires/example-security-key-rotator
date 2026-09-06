@echo off
setlocal
set "JAR=target\example-security-key-rotator.jar"
if not exist "%JAR%" (
  echo Build the application first with: mvn clean package
  exit /b 1
)
java -jar "%JAR%"
endlocal
