#include "frida-core.h"

GBytes *
_frida_agent_descriptor_clone_so (GBytes * so)
{
  /* TODO: update .so identity */
  return g_bytes_ref (so);
}

#ifdef HAVE_ANDROID
# include <android/log.h>
#include <selinux/selinux.h>
#define LOG_TAG "frida_Linjector"
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

gboolean frida_verifySELinux(guint pid) {
  char *backup_fromcon = NULL;
  if(getpidcon(pid, &backup_fromcon) == 0) {
    if(strstr(backup_fromcon, "untrusted_app") != NULL ||
      strstr(backup_fromcon, "u:r:app_zygote") != NULL ||
      strcmp(backup_fromcon, "u:r:zygote:s0") == 0 ||
      // strcmp(backup_fromcon, "u:r:isolated_app:s0") != NULL || 
      strcmp(backup_fromcon, "u:r:system_server:s0") == 0)
        return true;

  } else {
    ALOGE("backup_fromcon: null");
  }
  return false;
}
#endif