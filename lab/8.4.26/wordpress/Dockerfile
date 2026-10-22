FROM php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

ARG WORDPRESS_COMMIT=fc9832bef919c2a08541248db23af90d14ffb082
ARG WORDPRESS_TARBALL_SHA256=b48237e6bfc6f58c61251e03db7b2bb54c5291e582be3b43d01c3bfbb0d4de38

# Build only WordPress' mysqli dependency from the source bundled with the
# affected image. PHP and Apache retain their stock configuration.
RUN apt-get update \
 && apt-get install -y --no-install-recommends $PHPIZE_DEPS \
 && docker-php-ext-install mysqli \
 && apt-get purge -y --auto-remove $PHPIZE_DEPS \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/wordpress.tar.gz \
      "https://codeload.github.com/WordPress/WordPress/tar.gz/${WORDPRESS_COMMIT}" \
 && echo "${WORDPRESS_TARBALL_SHA256}  /tmp/wordpress.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/wordpress.tar.gz --strip-components=1 -C /var/www/html \
 && rm /tmp/wordpress.tar.gz \
 && chown -R www-data:www-data /var/www/html

COPY --chown=www-data:www-data src/wp-config.php /var/www/html/wp-config.php

# The verified fixture originated from a Windows checkout. Preserve its CRLF
# PHP source representation because parser allocations are part of the tested
# heap profile.
RUN find /var/www/html -type f -name '*.php' \
      -exec sed -i 's/$/\r/' '{}' +
