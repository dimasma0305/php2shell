FROM dokuwiki/dokuwiki:stable@sha256:c94c5f90716d65555eafd15a81710e65cf98af83107672dd9e9837d5c7fc585d AS dokuwiki_source

FROM php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

COPY --from=dokuwiki_source /var/www/html/ /var/www/html/

# Materialize the official image's storage setup during the build. The lab
# keeps it local to the container so a fresh `docker run` needs no volume.
RUN mkdir -p /storage/data /storage/conf /storage/lib/plugins /storage/lib/tpl \
 && cp -r /var/www/html/data.core/. /storage/data \
 && ln -sf /var/www/html/conf.core/license.php /storage/conf/license.php \
 && for ext in plugins tpl; do \
      for dir in /var/www/html/lib/$ext.core/*; do \
        ln -sf "$dir" "/storage/lib/$ext/$(basename "$dir")"; \
      done; \
    done \
 && chown -R www-data:www-data /storage /var/www/html
