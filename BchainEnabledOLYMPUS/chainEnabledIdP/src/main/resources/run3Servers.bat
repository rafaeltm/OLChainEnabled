@echo off 
set iniPort=9080
SETLOCAL ENABLEDELAYEDEXPANSION
FOR /L %%A IN (0,1,2) DO (
	set "var=resources\setup%%A.json"
	start java -jar bchain-usecase-IdP-jar-with-dependencies.jar !var! 
)
pause