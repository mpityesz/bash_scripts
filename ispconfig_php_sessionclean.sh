#! /bin/bash

#https://en.linuxportal.info/tutorials/troubleshooting/how-to-automatically-clean-php-session-files-left-in-web-files-tmp-directories-in-the-ispconfig-server-environment

# ISPConfig fiókok tmp könyvtárainak vizsgálata
SESSION_MAXLIFETIME=3600                                                                # Munkamenet élettartam másodpercekben (egyéni beállítás)
CLIENT_DIRS="/mnt/storage/wwwroot/clients"                                              # Kiindulási könyvtár: a kliens fájlstruktúra főkönyvtára

MINUTE=$((SESSION_MAXLIFETIME / 60))                                                    # kiszámítjuk a perceket a find parancs számára

# Fő ciklus: kliens könyvtárak
find $CLIENT_DIRS -maxdepth 1 -type d -name "client[0-9]*" |                            # A find megkeresi a clientX könyvtárakat, majd
    while read client_dir; do                                                           # ciklust készít a kapott eredményhalmazból
        WEB_DIRS=$client_dir                                                            # A web könyvtárakat beállítjuk az aktuális kliens könyvtárra.
                                                                                        # csak az áttekinthetőség miatt raktam ide
        # Belső ciklus: web könyvtárak
        find $WEB_DIRS -maxdepth 1 -type d -name "web[0-9]*" |                          # A find megkeresi a webY könyvtárakat, majd
            while read web_dir; do                                                      # ciklust készít a kapott eredményhalmazból
                tmp_dir=$(realpath $web_dir/tmp)                                        # A tmp könyvtárat a teljes útvonallal állítjuk össze,
                                                                                        # ezt a realpath paranccsal nyerjük ki a relatív útvonalból, amit a find-től kaptunk.
                find $tmp_dir -type f -name 'sess_*' -cmin "+$MINUTE" -delete           # elévült munkamenet fájlok törlése
            done
        echo                                                                            # plusz üres sor a kliensek között, hogy áttekinthetőbb legyen a kimenet, ha több kliens van.
    done
