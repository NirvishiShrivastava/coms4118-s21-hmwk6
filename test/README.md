$ ./inspect_pages 1
PID matched with subdirectory : 1.systemd
Reading Files in Directory: /mnt/1.systemd
# of Total Pages: 2298
# of Zero Pages: 28


$ ./map_pages
CASE 1 - Allocating heap memory worth 20 pages
================================================
PID matched with subdirectory : 1759.map_pages
Reading Files in Directory: /mnt/1759.map_pages
# of Total Pages: 287
# of Zero Pages: 0


CASE 2 - Mapping 10 Zero Pages to value 0 
================================================
PID matched with subdirectory : 1759.map_pages
Reading Files in Directory: /mnt/1759.map_pages
# of Total Pages: 297
# of Zero Pages: 10

Press enter to transform few pages to non-zero pages:


CASE 3 - Transforming 4 pages to Non-Zero Pages
================================================
PID matched with subdirectory : 1759.map_pages
Reading Files in Directory: /mnt/1759.map_pages
# of Total Pages: 297
# of Zero Pages: 6

Press enter to scrub those 4 pages back to zero pages:


CASE 4 - Mapping all pages back to Zero Pages
================================================
PID matched with subdirectory : 1759.map_pages
Reading Files in Directory: /mnt/1759.map_pages
# of Total Pages: 297
# of Zero Pages: 10

