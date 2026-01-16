<?php
class GameState{
    public $hash = null;
    public $realhash = null;
    public $score = 0;
}


$gameState = new GameState();
$gameState->score = 10000000;
$gameState->realhash = null;
$gameState->hash = &$gameState->realhash;
echo base64_encode(serialize($gameState));
?>
