@echo off
netstat -ano -p tcp | findstr LISTENING
