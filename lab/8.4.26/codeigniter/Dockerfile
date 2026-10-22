FROM composer:2.8.12@sha256:5248900ab8b5f7f880c2d62180e40960cd87f60149ec9a1abfd62ac72a02577c AS composer

FROM php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

ARG APPSTARTER_VERSION=4.7.4
ARG APPSTARTER_TARBALL_SHA256=9191571d41ed3cff10880fba7a76e0b6d6a35da46bcbf0c743bf6ae5d2c464e9

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      $PHPIZE_DEPS libicu-dev unzip \
 && docker-php-ext-install -j "$(nproc)" intl \
 && apt-get purge -y --auto-remove $PHPIZE_DEPS \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer /usr/bin/composer /usr/local/bin/composer
COPY composer.lock /tmp/codeigniter-composer.lock

RUN curl -fsSLo /tmp/codeigniter.tar.gz \
      "https://codeload.github.com/codeigniter4/appstarter/tar.gz/refs/tags/v${APPSTARTER_VERSION}" \
 && echo "${APPSTARTER_TARBALL_SHA256}  /tmp/codeigniter.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/codeigniter.tar.gz --strip-components=1 -C /var/www/html \
 && rm /tmp/codeigniter.tar.gz \
 && cp /tmp/codeigniter-composer.lock /var/www/html/composer.lock \
 && composer install --working-dir=/var/www/html \
      --no-dev --no-interaction --prefer-dist --optimize-autoloader \
 && chown -R www-data:www-data /var/www/html/writable

RUN sed -ri 's!/var/www/html!&/public!g' \
      /etc/apache2/sites-available/*.conf \
      /etc/apache2/apache2.conf \
      /etc/apache2/conf-available/*.conf \
 && a2enmod rewrite \
 && { echo '<Directory /var/www/html/public>'; \
      echo '  AllowOverride All'; \
      echo '  Require all granted'; \
      echo '</Directory>'; \
    } > /etc/apache2/conf-available/codeigniter.conf \
 && a2enconf codeigniter

WORKDIR /var/www/html/public
