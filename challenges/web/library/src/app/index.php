<?php
// NOTE: Flag is in /flag.txt
$AVAILABLE_BOOKS = [
    '$2a$12$iamalibrary1234567890uuAPtGGPKQMupW3gyswRSuSp.SE.rFiW' => 'books/three_hundred_of_the_best_ancient_chinese_profundities_by_sun_tzu/book.txt',
    '$2a$12$iamalibrary1234567890uV9cwXj27iJLZnz3vEjyeheS2SDeLMfO' => 'books/a_fable_by_aesop/book.txt',
];

if (isset($_GET['file']) && isset($_GET['hash'])) {
    $file_name = (string) $_GET['file'];
    $provided_hash = (string) $_GET['hash'];
    if (isset($AVAILABLE_BOOKS[$provided_hash]) && password_verify($file_name, $provided_hash)) {
        if (file_exists($file_name)) {
            header("Content-Type: text/plain; charset=utf-8");
            readfile($file_name);
            exit();
        } else {
            http_response_code(404);
            exit("Sorry, the book file seems to be missing from our shelves.");
        }
    }
    http_response_code(403);
    exit("Access denied. The provided file or hash is not valid for our library.");
} else {
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Blahaj Libraries</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; margin: 2em; background-color: #f4f4f4; color: #333; }
        .container { max-width: 800px; margin: auto; background: #fff; padding: 20px 30px; border-radius: 8px; box-shadow: 0 2px 15px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
        p { font-size: 1.1em; }
        ul { list-style-type: none; padding: 0; }
        li { margin: 15px 0; padding: 10px; border-left: 4px solid #3498db; background-color: #f8f9fa; transition: background-color 0.2s ease-in-out; }
        li:hover { background-color: #ecf0f1; }
        a { text-decoration: none; color: #2980b9; font-weight: bold; font-size: 1.1em; }
        a:hover { text-decoration: underline; }
        code { background-color: #eee; padding: 2px 4px; border-radius: 4px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to Blahaj Libraries!</h1>
        <p>
            To ensure only authorized books are accessed, each book requires a unique security hash to be read.
            Please select a book from the public collection below.
        </p>
        <hr>
        <h2>Our Collection</h2>
        <ul>
            <?php
            foreach ($AVAILABLE_BOOKS as $hash => $file) {
                $directory_path = dirname($file);
                $book_slug = basename($directory_path);
                $title = ucwords(str_replace('_', ' ', $book_slug));
                
                $url = htmlspecialchars($_SERVER['PHP_SELF']) . '?file=' . urlencode($file) . '&hash=' . urlencode($hash);
                echo "<li><a href=\"{$url}\">Read: {$title}</a></li>\n";
            }
            ?>
        </ul>
    </div>
</body>
</html>
<?php
}
?>