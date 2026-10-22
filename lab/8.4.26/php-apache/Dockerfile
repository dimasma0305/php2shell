FROM php@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a

# Deliberately small endpoint: no session_start(), framework, or custom php.ini.
RUN printf '%s\n' '<?php header("Content-Type: text/plain"); echo "php2shell lab\\n";' \
      > /var/www/html/index.php \
 && chown -R www-data:www-data /var/www/html
