window.dataLayer = window.dataLayer || [];

function proceedToDestination() {
    window.location = document.getElementById('url').getAttribute('data-href')
}

var secondsUntilRedirect = 6

function handlePlural() {
    if (secondsUntilRedirect == 1) {
        document.getElementById('s').textContent = ''
    } else {
        document.getElementById('s').textContent = 's'
    }
}

var intervalId = setInterval(function(){
    secondsUntilRedirect -= 1
    document.getElementById('countdown-seconds').textContent = secondsUntilRedirect
    handlePlural()
    if (secondsUntilRedirect > 0) {
        return
    }
    clearInterval(intervalId)
    window.location = document.getElementById('url').getAttribute('data-href')
}, 1000)

;(function() {
    document.getElementById('skip').addEventListener('click', function (e) {
        window.location = document.getElementById('url').getAttribute('data-href')
    })
})()
