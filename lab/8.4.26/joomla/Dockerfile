FROM joomla@sha256:7a81f74409c744d955144c91cf4e140386f18751696a32921d93fc8821f221af AS joomla_source

FROM php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libfreetype6-dev libicu-dev libjpeg62-turbo-dev libonig-dev \
      libpng-dev libzip-dev \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j "$(nproc)" gd intl mbstring mysqli pdo_mysql zip \
 && rm -rf /var/lib/apt/lists/*

COPY --from=joomla_source --chown=www-data:www-data /usr/src/joomla/ /var/www/html/

RUN mkdir -p /var/www/html/cache /var/www/html/images \
      /var/www/html/logs /var/www/html/tmp \
 && chown -R www-data:www-data /var/www/html
