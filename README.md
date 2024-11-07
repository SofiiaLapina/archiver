# archiver

gcc -o archive_tool main.c archive.c crypto.c -lssl -lcrypto -lz

Usages:
For creating archive:
archive_tool.exe -c "path\to\archive\name.zip" "path\to\archive\contents" -p <password> | -g <key>

For extracting archive:
archive_tool.exe -x "path\to\archive\name.zip" "path\to\the\place\where\to\extract\the\archive" -p <password> | -g <key>
