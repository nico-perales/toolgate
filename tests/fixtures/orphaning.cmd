@echo off
rem A server that exits at once but leaves a process of its own running, holding
rem its output open. That process writes its pid to the file named by the first
rem argument; this script waits for the file, so the pid is known before it exits.
start "" /b node -e "require('fs').writeFileSync(process.argv[1], String(process.pid)); setInterval(function () {}, 1000);" "%~1"
node -e "while (!require('fs').existsSync(process.argv[1])) {}" "%~1"
