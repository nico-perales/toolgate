@echo off
rem A server that ignores end-of-file, launched through cmd.exe the way npx is.
rem It writes its pid to the file named by its first argument.
node -e "require('fs').writeFileSync(process.argv[1], String(process.pid)); process.stdin.resume(); setInterval(function () {}, 1000);" "%~1"
