FROM mediawiki@sha256:276fd8c601efd6a607747f5b0a9de4649b80d4927b905fba0e77a62c0adf4af7 AS mediawiki_source

FROM php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

RUN apt-get update \
 && apt-get install -y --no-install-recommends $PHPIZE_DEPS libicu-dev \
 && docker-php-ext-install -j "$(nproc)" calendar intl mysqli \
 && apt-get purge -y --auto-remove $PHPIZE_DEPS \
 && rm -rf /var/lib/apt/lists/* \
 && a2enmod rewrite \
 && { echo '<Directory /var/www/html>'; \
      echo '  RewriteEngine On'; \
      echo '  RewriteCond %{REQUEST_FILENAME} !-f'; \
      echo '  RewriteCond %{REQUEST_FILENAME} !-d'; \
      echo '  RewriteRule ^ %{DOCUMENT_ROOT}/index.php [L]'; \
      echo '</Directory>'; \
    } > /etc/apache2/conf-available/short-url.conf \
 && a2enconf short-url

COPY --from=mediawiki_source --chown=www-data:www-data /var/www/html/ /var/www/html/

# This lab uses the bundled, directly reachable Scribunto constants endpoint.
# The proof is fetched as a static file under MediaWiki's writable images tree.
RUN mkdir -p /var/www/html/images \
 && chown -R www-data:www-data /var/www/html/images
