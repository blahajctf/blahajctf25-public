<?php
define('SERVER_SECRET', 'highsch00l1sn0thingl1k3p3rson4'); // this is different on the server
define('HASH_ROUNDS', 10);

class GameState
{
    public $hash = null;
    public $realhash = null;
    public $score = 0;
}

function calculate_security_hash(int $score): string{
    $string_to_hash = $score . SERVER_SECRET;
    for ($i = 0; $i < HASH_ROUNDS; $i++) {
        $string_to_hash = hash('sha256', $string_to_hash);
    }

    return $string_to_hash;
}

$gameState = null;
$message = "Perform more to gain more members in the Blast Fan Club!";
$is_winner = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['gameState'])) {
    $serializedData = base64_decode($_POST['gameState']);
    $gameState = unserialize($serializedData, ['allowed_classes' => ['GameState']]);

    if ($gameState instanceof GameState) {
    
        $gameState->realhash = calculate_security_hash($gameState->score);
        
        if (hash_equals($gameState->hash, $gameState->realhash)) {
            $gameState->score++;
            if ($gameState->score >= 707707707707) {
              $message = "Congratulations! You win!";
              $flag = "[FLAG]";
                $is_winner = true;
            } else {
              $message = "🍓 You've gained more fans! ".(707707707707 - $gameState->score)." more fans to go! 🍓";
              $flag = "THE BLACK STONES";
            }

        } else {
            $message = "Error: Data tampering detected! Resetting fan count.";
            $gameState = new GameState();
            $gameState->score = 0;
        }

    } else {
        $message = "Error: Invalid data received. Resetting fan count.";
        $gameState = new GameState();
        $gameState->score = 0;
    }

} else {
    $gameState = new GameState();
    $gameState->score = 0;
}


$gameState->hash = calculate_security_hash($gameState->score);
$gameState->realhash = null;
$serializedStateForClient = base64_encode(serialize($gameState));
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BLAST PRIVATE FAN CLUB</title>

    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=New+Rocker&family=Odibee+Sans&display=swap" rel="stylesheet">
    <style>

        @font-face {
            font-family: header;
            src: url(font.ttf);
        }

        body { 
font-family: 'Odibee Sans'; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: black; margin: 0;
         background:
        linear-gradient(
          rgba(0, 0, 0, 0.9), 
          rgba(0, 0, 0, 0.9)
        ),
        url('bg.jpeg');
        background-repeat: no-repeat;
        background-size: cover;
        }
        .container { 
position: relative; text-align: center; padding: 40px; background-color: #eee; 
background-image: url('texture.png');
background-size: cover;


border-radius: 2px; filter: drop-shadow(2px 2px 0px #ff028d)}
        
        h1 { color: #ff028d; font-family: "header";
            filter: drop-shadow(2px 2px 0px black);          
        }


        .score { font-size: 3em; color: #ff028d; margin: 20px 0; filter: drop-shadow(2px 2px 0px black) drop-shadow(3px 3px 0px #cc2153);}

        .submit {
        }
        .message { margin-bottom: 20px; font-style: italic; color: #555; min-height: 20px;}
        button {           border-bottom: 2px solid black; border-right: 2px solid black;
; font-family: 'Odibee Sans'; padding: 10px 20px; font-size: 1.2em; cursor: pointer; border: none; background-color: #ff028d;; color: white;}
        button:hover { background-color: #cc2153; }
        button:disabled { background-color: #cccccc; cursor: not-allowed; }
        .win-message { font-size: 2em; color: #cc2153; font-weight: bold; }

        .label {
            position: absolute;
            font-family: 'New Rocker';
            font-weight: 400;
            bottom: -20px; right: -50px;
            transform: rotate(-12deg);
            background-color: black;
            font-size: 25px;
            padding: 5px;
            color: white;
        }

        .container::after {
            position: absolute;
            content: 'sponsored by Vivienne Sharkwood.';
            bottom: 10px; left: 20px;
            opacity: 0.5; 
        }

        .chibis {
          width: 200px; 
          position: absolute;
          top: -25%; left:50%; transform: translateX(-50%);
          }

        .stars {
          width: 200px; position: absolute;
          font-size: 45px;
          line-height: 30px;
          top: 50%; left: -100px; transform:translateY(-50%);
        }
        h1{ margin: 0 ;}
    </style>
</head>
<body>
    
<body>
    <audio id="clickSound" src="click.mp3" preload="auto"></audio>
    
    <div>
        <div class="container">
            <div class='stars'>★<br>★<br>★<br>★<br>★<br>★<br>★</div>
            <h1>BLAST&nbsp;&nbsp;PRIVATE&nbsp;&nbsp;FAN&nbsp;&nbsp;CLUB!</h1>
            
            <p class="message"><?php echo htmlspecialchars($message); ?></p>
            
            <?php if ($is_winner): ?>

                <div class="score win-message">You reached 707707707707 fans!</div>
                <form method="GET" action=""><button type="submit">Play Again</button></form>
            <?php else: ?>
                <div class="score"><?php echo htmlspecialchars($gameState->score); ?></div>
                <form id="gameForm" method="POST" action="">
                    <input type="hidden" name="gameState" value="<?php echo $serializedStateForClient; ?>">
                    <button type="submit">PERFORM</button>
                </form>
            <?php endif; ?>

          <img src='chibi.png' class=chibis>
          <?php if ($is_winner): ?>
          <div class='label'>blahaj{why_d0_s3rial1sed_obj3cts_h4v3_p0int3rs_2955}</div>
          <?php else: ?>
          <div class='label'>THE BLACK STONES</div>
          <?php endif; ?>
          </div>
    </div>
    <script>
        const gameForm = document.getElementById('gameForm');
        const clickSound = document.getElementById('clickSound');
        if (gameForm) {
            gameForm.addEventListener('submit', function(event) {
                event.preventDefault();
                clickSound.currentTime = 0;
                clickSound.play();
                setTimeout(function() {
                    gameForm.submit();
                }, 300);
            });
        }
    </script>
</body>
</html>
