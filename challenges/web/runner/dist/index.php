<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure command runner</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .terminal {
            background-color: #000000;
            color: #00ff00;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', Courier, monospace;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card shadow-sm">
                    <div class="card-header bg-primary text-white">
                        <h1 class="h4 mb-0">Secure command runner</h1>
                    </div>
                    <div class="card-body">
                        <p class="card-text">Please enter the command you wish to run.</p>
                        <form method="POST" action="">
                            <div class="mb-3">
                                <label for="cmd" class="form-label"><b>Command to run:</b></label>
                                <input type="text" class="form-control" id="cmd" name="cmd">
                            </div>
                            <button type="submit" class="btn btn-primary w-100">Run Command</button>
                        </form>
                    </div>
                </div>

                <?php
                if (isset($_REQUEST['cmd'])):
                ?>
                <div class="card shadow-sm mt-4">
                    <div class="card-header">
                        <h2 class="h5 mb-0">Results for: <?= htmlspecialchars($_REQUEST['cmd']) ?></h2>
                    </div>
                    <div class="card-body">
                        <div class="terminal">
                            <?php
                            if (isset($_REQUEST['cmd'])) {
                                $cmd = $_REQUEST['cmd'];
                                if (!is_string($cmd) || preg_match('/(.)((?1))*/i', $cmd)) {
                                    echo 'You dare hack our systems! Begone hacker!';
                                } else {
                                    echo 'Output of command "'.$cmd.'": <br>';
                                    system($cmd);
                                }
                            }
                            ?>
                        </div>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</body>
</html>