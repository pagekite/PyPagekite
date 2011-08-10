#!/bin/sh

my_date=`date +"%d/%m/%Y %H:%M"`

# Log starting the service
echo "[$my_date] Starting service" > ./log

# Loop over to restart the client on case of a crash
while [ -f /home/pagekite/pagekite.lua ]
do
  lua ./pagekite.lua
  sleep 10
  # Log the crash
  my_date=`date +"%d/%m/%Y %H:%M"`
  echo "[$my_date] Service crashed! Restarting service" >> ./log
done

