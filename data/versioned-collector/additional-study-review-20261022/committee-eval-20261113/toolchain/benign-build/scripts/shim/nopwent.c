/* Link-time shim (used with -Wl,--wrap=getpwuid) for the SQLite shell linked statically against glibc < 2.34.
 * Such a static glibc resolves getpwuid() by dlopen()ing the running system's libnss_files.so.2; with a newer
 * system glibc (host 2.35, guest 2.43) the program crashes (SIGSEGV) before doing any work. The shell only calls
 * getpwuid() to locate the home directory for ~/.sqliterc and then falls back to $HOME, so a NULL result keeps
 * its observable behaviour. No source file of SQLite is modified. */
#include <stddef.h>
struct passwd;
struct passwd *__wrap_getpwuid(unsigned int uid) { (void)uid; return NULL; }
