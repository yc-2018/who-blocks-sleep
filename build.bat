@echo off
chcp 65001 >nul
cd /d "%~dp0"
rem 重新打包 who-blocks-sleep.exe
rem app.manifest 提供管理员权限 + DPI 感知声明；
rem 必须同时加 --uac-admin，否则 PyInstaller 会把清单里的
rem requestedExecutionLevel 重置成 asInvoker。
set "ICO=%~dp0assets\app.ico"
set "MAN=%~dp0assets\app.manifest"
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin ^
  --manifest "%MAN%" --icon "%ICO%" --add-data "%ICO%;assets" ^
  --name "who-blocks-sleep" --distpath "%~dp0" --workpath "%~dp0build" --specpath "%~dp0build" ^
  "%~dp0src\who_blocks_sleep.py"
echo.
echo 打包完成：%~dp0who-blocks-sleep.exe
pause
