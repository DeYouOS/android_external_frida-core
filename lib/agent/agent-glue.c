#include "frida-agent.h"

#include "frida-base.h"
#include "frida-payload.h"

#ifdef HAVE_ANDROID
# include <jni.h>
#include <selinux/selinux.h>
#include <android/log.h>
#define LOG_TAG "frida_agent"
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)

# if __ANDROID_API__ < __ANDROID_API_L__
#  include <signal.h>
# endif
#endif
#ifdef HAVE_GIOOPENSSL
# include <gioopenssl.h>
#endif

void
_frida_agent_environment_init (void)
{
#ifdef HAVE_MUSL
  static gboolean been_here = FALSE;

  if (been_here)
    return;
  been_here = TRUE;
#endif

  gum_init_embedded ();
  gio_init ();

  g_thread_set_garbage_handler (_frida_agent_on_pending_thread_garbage, NULL);

#ifdef HAVE_GIOOPENSSL
  g_io_module_openssl_register ();
#endif

  gum_script_backend_get_type (); /* Warm up */
  frida_error_quark (); /* Initialize early so GDBus will pick it up */

#if defined (HAVE_ANDROID) && __ANDROID_API__ < __ANDROID_API_L__
  /*
   * We might be holding the dynamic linker's lock, so force-initialize
   * our bsd_signal() wrapper on this thread.
   */
  bsd_signal (G_MAXINT32, SIG_DFL);
#endif
}

void
_frida_agent_environment_deinit (void)
{
#ifndef HAVE_MUSL
  gum_shutdown ();
  gio_shutdown ();
  glib_shutdown ();

  gio_deinit ();
  gum_deinit_embedded ();

  frida_run_atexit_handlers ();

# ifdef HAVE_DARWIN
  /* Do what frida_deinit_memory() does on the other platforms. */
  gum_internal_heap_unref ();
# endif
#endif
}

#ifdef HAVE_ANDROID

jint
JNI_OnLoad (JavaVM * vm, void * reserved)
{
  FridaAgentBridgeState * state = reserved;

  frida_agent_main (state->agent_parameters, &state->unload_policy, state->injector_state);

  return JNI_VERSION_1_6;
}

gboolean _frida_agent_environment_enable(void) {
  char *backup_fromcon = NULL;
  if(getcon(&backup_fromcon) == 0) {
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

void frida_agent_environment_error (const gchar* fmt, ...) {

  va_list ap;
  va_start(ap, fmt);
  __android_log_vprint(ANDROID_LOG_ERROR, LOG_TAG, fmt, ap);
  va_end(ap);
}

#endif