FROM php:8.5-cli-alpine
COPY bin/php-security-check /app/bin/php-security-check
COPY data /app/data
WORKDIR /project
ENTRYPOINT ["php", "/app/bin/php-security-check"]
